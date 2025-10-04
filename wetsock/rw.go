package wetsock

import (
	"crypto/rand"
	"errors"
	"log"
	"math/big"
	"reflect"
	"time"

	"github.com/gorilla/websocket"
	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/vmihailenco/msgpack/v5"
)

// ----------------------------------------------------------------------------
// Повідомлення «на дроті» у форматі MessagePack
// ----------------------------------------------------------------------------

type mpMessage struct {
	// На бінарі немає сенсу тримати id як string — використовуємо uint64
	ID     uint64             `msgpack:"id,omitempty"`
	Func   string             `msgpack:"fn,omitempty"`
	Args   msgpack.RawMessage `msgpack:"args,omitempty"`
	Result msgpack.RawMessage `msgpack:"result,omitempty"`
	Error  *wsrpc.Error       `msgpack:"error"`
}

// ----------------------------------------------------------------------------
// Методи Codec (MessagePack-версія)
// ----------------------------------------------------------------------------

// ReadMessage: читаємо бінарні дані, дешифруємо, потім розбираємо MessagePack
func (c *codec) ReadMessage(msg *wsrpc.Message) error {
	mt, data, err := c.WS.ReadMessage()
	if err != nil {
		// Перевірка закриття
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			log.Println("[WebSocket] Соединение закрыто:", err)
			return err
		}
		log.Println("[WebSocket] Ошибка чтения сообщения:", err)
		return err
	}
	if mt != websocket.BinaryMessage {
		return errors.New("очікувався бінарний зашифрований формат, але прийшов інший тип")
	}

	// Дешифруємо
	decryptedBufPtr, err := c.decryptMessage(data)
	if err != nil {
		log.Println("[WebSocket] Ошибка дешифрования:", err)
		return err
	}

	// Розбираємо MessagePack
	var mm mpMessage
	if err := msgpack.Unmarshal(*decryptedBufPtr, &mm); err != nil {
		log.Println("[WebSocket] Ошибка парсинга MessagePack:", err)
		return err
	}

	// Заповнюємо wsrpc.Message (Args/Result кладемо як RawMessage/[]byte)
	msg.ID = mm.ID
	msg.Func = mm.Func
	msg.Args = mm.Args // []byte (msgpack.RawMessage) — розпакуємо пізніше
	msg.Result = mm.Result
	msg.Error = mm.Error
	return nil
}

// WriteMessage: формуємо mpMessage, серіалізуємо у MessagePack, шифруємо, відправляємо
func (c *codec) WriteMessage(msg *wsrpc.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closing {
		log.Println("[WebSocket] Попытка отправки сообщения после закрытия соединения!")
		return errors.New("соединение закрывается, отправка невозможна")
	}

	// Паддінг 0..MaxPad за допомогою crypto/rand
	n, err := rand.Int(rand.Reader, big.NewInt(MaxPad+1))
	if err != nil {
		return err
	}
	msg.Pad = randLetters(int(n.Int64()))

	// Підготуємо Args/Result як сирі msgpack-байти
	var argsRaw, resRaw msgpack.RawMessage

	// Args
	switch v := msg.Args.(type) {
	case nil:
		// leave nil
	case msgpack.RawMessage:
		argsRaw = v
	case []byte:
		// вважаємо, що це вже msgpack-байти
		argsRaw = msgpack.RawMessage(v)
	default:
		b, err := msgpack.Marshal(v)
		if err != nil {
			return err
		}
		argsRaw = msgpack.RawMessage(b)
	}

	// Result
	switch v := msg.Result.(type) {
	case nil:
		// leave nil
	case msgpack.RawMessage:
		resRaw = v
	case []byte:
		resRaw = msgpack.RawMessage(v)
	default:
		b, err := msgpack.Marshal(v)
		if err != nil {
			return err
		}
		resRaw = msgpack.RawMessage(b)
	}

	// Формуємо MessagePack-повідомлення
	wire := mpMessage{
		ID:     msg.ID,
		Func:   msg.Func,
		Args:   argsRaw,
		Result: resRaw,
		Error:  msg.Error,
	}

	rawMP, err := msgpack.Marshal(&wire)
	if err != nil {
		return err
	}

	// Шифруємо
	encrypted, err := c.encryptMessage(rawMP)
	if err != nil {
		return err
	}

	// Відправляємо у sendChan з таймаутом
	c.wg.Add(1)
	select {
	case c.sendChan <- encrypted:
		return nil
	case <-time.After(TimeOutWrite * time.Second):
		c.wg.Done()
		log.Println("[WebSocket] Таймаут отправки сообщения!")
		return errors.New("таймаут отправки сообщения")
	}
}

// ----------------------------------------------------------------------------
// Додаткові методи (інтерфейс wsrpc.Codec)
// ----------------------------------------------------------------------------

// UnmarshalArgs: msg.Args (msgpack.RawMessage/[]byte) -> args
func (c *codec) UnmarshalArgs(msg *wsrpc.Message, args interface{}) error {
	if msg.Args == nil {
		return nil
	}
	switch raw := msg.Args.(type) {
	case msgpack.RawMessage:
		return msgpack.Unmarshal(raw, args)
	case []byte:
		return msgpack.Unmarshal(raw, args)
	default:
		// якщо сюди випадково поклали вже розпаковане значення — нічого не робимо
		return nil
	}
}

// UnmarshalResult: msg.Result (msgpack.RawMessage/[]byte) -> result
func (c *codec) UnmarshalResult(msg *wsrpc.Message, result interface{}) error {
	if msg.Result == nil {
		return errors.New("wsrpc.msgpack response must set result")
	}
	switch raw := msg.Result.(type) {
	case msgpack.RawMessage:
		return msgpack.Unmarshal(raw, result)
	case []byte:
		return msgpack.Unmarshal(raw, result)
	default:
		return errors.New("wsrpc.msgpack result has unexpected type")
	}
}

// FillArgs: якщо RPC-метод приймає *websocket.Conn — підставляємо активний conn
func (c *codec) FillArgs(arglist []reflect.Value) error {
	for i := 0; i < len(arglist); i++ {
		if _, ok := arglist[i].Interface().(*websocket.Conn); ok {
			arglist[i] = reflect.ValueOf(c.WS)
		}
	}
	return nil
}
