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

func (r *Registry) GetFunctionsName() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	str := make([]string, 0, len(r.functions))
	for key, _ := range r.functions {
		str = append(str, key)
	}

	return str
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
	perm  *Permission

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
