// Bidirectional RPC with JSON messages.
//
// Uses net/rpc, is inspired by net/rpc/jsonrpc, but does more than
// either:
//
// - fully bidirectional: server can call RPCs on the client
// - incoming messages with seq 0 are "untagged" and will not
//   be responded to
//
// This allows one to do RPC over websockets without sacrifing what
// they are good for: sending immediate notifications.
//
// While this is intended for websockets, any io.ReadWriteCloser will
// do.

package wsrpc

import (
	"fmt"
	"log"
	"net/rpc"
	"reflect"
	"sync"
)

type function struct {
	receiver reflect.Value
	method   reflect.Method
	args     reflect.Type
	reply    reflect.Type
}

// Registry — це набір сервісів з методами, які можна викликати віддалено.
// Кожен метод має назву у форматі SERVICE.METHOD.
//
// Один реєстр (Registry) призначений для використання з кількома Endpoints.
// Це розділення існує тому, що реєстрація сервісів може бути повільною операцією.

type Registry struct {
	// protects services
	mu        sync.RWMutex
	functions map[string]*function
}

func getRPCMethodsOfType(object interface{}) ([]*function, error) {
	var fns []*function

	type_ := reflect.TypeOf(object)

	for i := 0; i < type_.NumMethod(); i++ {
		method := type_.Method(i)

		if method.PkgPath != "" {
			// skip unexported method
			continue
		}
		if method.Type.NumIn() < 3 {
			return nil, fmt.Errorf("wsrpc.RegisterService: method %T.%s is missing request/reply arguments", object, method.Name)
		}
		if method.Type.In(2).Kind() != reflect.Ptr {
			return nil, fmt.Errorf("wsrpc.RegisterService: method %T.%s reply argument must be a pointer type", object, method.Name)
		}
		var tmp error
		if method.Type.NumOut() != 1 || method.Type.Out(0) != reflect.TypeOf(&tmp).Elem() {
			return nil, fmt.Errorf("wsrpc.RegisterService: method %T.%s must return error", object, method.Name)
		}

		fn := &function{
			receiver: reflect.ValueOf(object),
			method:   method,
			args:     method.Type.In(1),
			reply:    method.Type.In(2).Elem(),
		}
		fns = append(fns, fn)
	}

	if len(fns) == 0 {
		return nil, fmt.Errorf("wsrpc.RegisterService: type %T has no exported methods of suitable type", object)
	}
	return fns, nil
}

// RegisterService реєструє всі експортовані методи service, дозволяючи
// викликати їх віддалено. Імена методів матимуть формат SERVICE.METHOD,
// де SERVICE — це назва типу або об’єкта, переданого при реєстрації,
// а METHOD — назва кожного методу.
//
// Очікується, що методи мають щонайменше два аргументи — args та reply.
// Reply має бути вказівником, і метод повинен заповнити його результатом.
// Типи аргументів обмежені лише вимогами codec щодо можливості їх серіалізації
// для передачі. Наприклад, для wetsock аргументи та відповідь мають
// серіалізуватись у JSON.
//
// Решта аргументів заповнюється за можливості, якщо їх типи відомі wsrpc
// та використовуваному codec.
//
// Методи повинні повертати значення типу error.

func (r *Registry) RegisterService(object interface{}) {
	methods, err := getRPCMethodsOfType(object)
	if err != nil {
		// programmer error
		panic(err)
	}

	serviceName := reflect.Indirect(reflect.ValueOf(object)).Type().Name()

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, fn := range methods {
		name := serviceName + "." + fn.method.Name
		r.functions[name] = fn
	}
}

// NewRegistry creates a new Registry.
func NewRegistry() *Registry {
	r := &Registry{}
	r.functions = make(map[string]*function)
	return r
}

// Codec читає повідомлення від вузла та записує повідомлення до вузла.
type Codec interface {
	ReadMessage(*Message) error

	// WriteMessage може викликатися одночасно з різних потоків.
	// Codec повинен самостійно забезпечити потокобезпечність.

	WriteMessage(*Message) error

	UnmarshalArgs(msg *Message, args interface{}) error
	UnmarshalResult(msg *Message, result interface{}) error

	Close() error
}

// FillArgser — це необов’язковий інтерфейс, який може реалізувати Codec,
// щоб надати додаткову інформацію методам RPC.
//
// Codec повинен перебирати значення і заповнювати ті типи, які він розпізнає.
//
// Типовим прикладом використання є надання RPC-методу доступу до
// базового з’єднання, щоб отримати IP-адресу віддаленого вузла.
type FillArgser interface {
	FillArgs([]reflect.Value) error
}

// Endpoint керує станом одного з'єднання (через Codec) та обробляє
// очікуючі виклики — як вхідні, так і вихідні.
type Endpoint struct {
	codec Codec

	client struct {
		// protects seq and pending
		mutex   sync.Mutex
		seq     uint64
		pending map[uint64]*rpc.Call
	}

	server struct {
		registry *Registry
		running  sync.WaitGroup
	}
}

// Пустий реєстр без зареєстрованих функцій.
var dummyRegistry = NewRegistry()

// NewEndpoint створює нову кінцеву точку, яка використовує codec для взаємодії з вузлом.
// Щоб обробляти повідомлення, потрібно викликати endpoint.Serve;
// це зроблено для того, щоб можна було обробити помилки.
// Registry може бути nil, якщо не потрібно надавати callable-об'єкти з цього вузла.

func NewEndpoint(codec Codec, registry *Registry) *Endpoint {
	if registry == nil {
		registry = dummyRegistry
	}
	e := &Endpoint{}
	e.codec = codec
	e.server.registry = registry
	e.client.pending = make(map[uint64]*rpc.Call)
	return e
}

func (e *Endpoint) serve_request(msg *Message) error {
	e.server.registry.mu.RLock()
	fn := e.server.registry.functions[msg.Func]
	e.server.registry.mu.RUnlock()
	if fn == nil {
		msg.Error = &Error{Msg: "No such function."}
		msg.Func = ""
		msg.Args = nil
		msg.Result = nil
		err := e.send(msg)
		if err != nil {
			// ну що ж, ми не можемо повідомити клієнту про проблему...
			return err
		}
		return nil
	}

	e.server.running.Add(1)
	go func(fn *function, msg *Message) {
		defer e.server.running.Done()
		e.call(fn, msg)
	}(fn, msg)
	return nil
}

func (e *Endpoint) serve_response(msg *Message) error {
	e.client.mutex.Lock()
	call, found := e.client.pending[msg.ID]
	delete(e.client.pending, msg.ID)
	e.client.mutex.Unlock()

	if !found {
		return fmt.Errorf("Server responded with unknown seq %v", msg.ID)
	}

	if msg.Error == nil {
		if call.Reply != nil {
			err := e.codec.UnmarshalResult(msg, call.Reply)
			if err != nil {
				call.Error = fmt.Errorf("Unmarshaling result: %v", err)
			}
		}
	} else {
		call.Error = rpc.ServerError(msg.Error.Msg)
	}

	// повідомити викликача, але ніколи не блокувати виконання
	select {
	case call.Done <- call:
	default:
	}

	return nil
}

// Обробляє повідомлення з цього з'єднання. Serve блокує виконання,
// обслуговуючи з'єднання до моменту, поки клієнт не відключиться або не виникне помилка.
func (e *Endpoint) Serve() error {
	defer e.codec.Close()
	defer e.server.running.Wait()
	for {
		var msg Message
		err := e.codec.ReadMessage(&msg)
		if err != nil {
			return err
		}

		if msg.Func != "" {
			err = e.serve_request(&msg)
		} else {
			err = e.serve_response(&msg)
		}
		if err != nil {
			return err
		}
	}
}

func (e *Endpoint) Close() error {
	return e.codec.Close()
}

func (e *Endpoint) send(msg *Message) error {
	return e.codec.WriteMessage(msg)
}

func (e *Endpoint) fillArgs(arglist []reflect.Value) {
	for i := 0; i < len(arglist); i++ {
		switch arglist[i].Interface().(type) {
		case *Endpoint:
			arglist[i] = reflect.ValueOf(e)
		}
	}
}

func (e *Endpoint) call(fn *function, msg *Message) {
	var args reflect.Value
	if fn.args.Kind() == reflect.Ptr {
		args = reflect.New(fn.args.Elem())
	} else {
		args = reflect.New(fn.args)
	}

	err := e.codec.UnmarshalArgs(msg, args.Interface())
	if err != nil {
		msg.Error = &Error{Msg: err.Error()}
		msg.Func = ""
		msg.Args = nil
		msg.Result = nil
		err = e.send(msg)
		if err != nil {
			// well, we can't report the problem to the client...
			e.codec.Close()
			return
		}
		return
	}
	if fn.args.Kind() != reflect.Ptr {
		args = args.Elem()
	}

	reply := reflect.New(fn.reply)

	num_args := fn.method.Type.NumIn()
	arglist := make([]reflect.Value, num_args, num_args)

	arglist[0] = fn.receiver
	arglist[1] = args
	arglist[2] = reply

	if num_args > 3 {
		for i := 3; i < num_args; i++ {
			arglist[i] = reflect.Zero(fn.method.Type.In(i))
		}
		// first fill what we can
		e.fillArgs(arglist[3:])

		// then codec fills what it can
		if filler, ok := e.codec.(FillArgser); ok {
			err = filler.FillArgs(arglist[3:])
			if err != nil {
				msg.Error = &Error{Msg: err.Error()}
				msg.Func = ""
				msg.Args = nil
				msg.Result = nil
				err = e.send(msg)
				if err != nil {
					// well, we can't report the problem to the client...
					e.codec.Close()
					return
				}
				return
			}
		}
	}

	retval := fn.method.Func.Call(arglist)
	erri := retval[0].Interface()
	if erri != nil {
		err := erri.(error)
		msg.Error = &Error{Msg: err.Error()}
		msg.Func = ""
		msg.Args = nil
		msg.Result = nil
		err = e.send(msg)
		if err != nil {
			// well, we can't report the problem to the client...
			e.codec.Close()
			return
		}
		return
	}

	msg.Error = nil
	msg.Func = ""
	msg.Args = nil
	msg.Result = reply.Interface()

	err = e.send(msg)
	if err != nil {
		// well, we can't report the problem to the client...
		e.codec.Close()
		return
	}
}

// Go викликає функцію асинхронно. Дивись net/rpc Client.Go.
func (e *Endpoint) Go(function string, args interface{}, reply interface{}, done chan *rpc.Call) *rpc.Call {
	call := &rpc.Call{}
	call.ServiceMethod = function
	call.Args = args
	call.Reply = reply
	if done == nil {
		done = make(chan *rpc.Call, 10)
	} else {
		if cap(done) == 0 {
			log.Panic("wsrpc: done channel is unbuffered")
		}
	}
	call.Done = done

	msg := &Message{
		Func: function,
		Args: args,
	}

	e.client.mutex.Lock()
	e.client.seq++
	msg.ID = e.client.seq
	e.client.pending[msg.ID] = call
	e.client.mutex.Unlock()

	// put sending in a goroutine so a malicious client that
	// refuses to read cannot ever make a .Go call block
	go e.send(msg)
	return call
}

// Call invokes the named function, waits for it to complete, and
// returns its error status. See net/rpc Client.Call
func (e *Endpoint) Call(function string, args interface{}, reply interface{}) error {
	call := <-e.Go(function, args, reply, make(chan *rpc.Call, 1)).Done
	return call.Error
}
