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

/*
// ----------------------------------------------------------------------------
// Методи, що вимагає wsrpc.Codec
// ----------------------------------------------------------------------------

type jsonMessage struct {
	ID     uint64          `json:"id,string,omitempty"`
	Func   string          `json:"fn,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *wsrpc.Error    `json:"error"`
}

// ReadMessage: читаємо бінарні дані, дешифруємо, потім розбираємо JSON
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
		return errors.New("ожидался бинарный шифрованный формат, а пришел другой тип")
	}

	// Дешифруємо
	decryptedBufPtr, err := c.decryptMessage(data)
	if err != nil {
		log.Println("[WebSocket] Ошибка дешифрования:", err)
		return err
	}

	// Розбираємо JSON
	var jm jsonMessage
	if err := json.Unmarshal(*decryptedBufPtr, &jm); err != nil {
		log.Println("[WebSocket] Ошибка парсинга JSON:", err)
		return err
	}

	// Заповнюємо wsrpc.Message
	msg.ID = jm.ID
	msg.Func = jm.Func
	msg.Args = jm.Args
	msg.Result = jm.Result
	msg.Error = jm.Error
	return nil
}

// WriteMessage: серіалізуємо msg у JSON, шифруємо й відправляємо в канал
func (c *codec) WriteMessage(msg *wsrpc.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closing {
		log.Println("[WebSocket] Попытка отправки сообщения после закрытия соединения!")
		return errors.New("соединение закрывается, отправка невозможна")
	}

	// сформувати паддінг довжиною 0..N байт
	// сформувати паддінг довжиною 0..MaxPad байт за допомогою crypto/rand
	n, err := rand.Int(rand.Reader, big.NewInt(MaxPad+1))
	if err != nil {
		return err
	}

	msg.Pad = randLetters(int(n.Int64()))
	// 1) Спочатку серіалізуємо у JSON
	rawJSON, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// 2) Шифруємо
	encrypted, err := c.encryptMessage(rawJSON)
	if err != nil {
		return err
	}

	// 3) Кладемо зашифровані дані у sendChan
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
// Додаткові методи (потрібні інтерфейсу wsrpc.Codec)
// ----------------------------------------------------------------------------

// UnmarshalArgs десеріалізує msg.Args -> ваші аргументи
func (c *codec) UnmarshalArgs(msg *wsrpc.Message, args interface{}) error {
	raw, ok := msg.Args.(json.RawMessage)
	if !ok || raw == nil {
		return nil
	}
	err := json.Unmarshal(raw, args)
	if err != nil {
		log.Println("[WebSocket] Ошибка десериализации аргументов:", err)
	}
	return err
}

// UnmarshalResult десеріалізує msg.Result -> змінна result
func (c *codec) UnmarshalResult(msg *wsrpc.Message, result interface{}) error {
	raw, ok := msg.Result.(json.RawMessage)
	if !ok || raw == nil {
		return errors.New("wsrpc.jsonmsg response must set result")
	}
	err := json.Unmarshal(raw, result)
	if err != nil {
		log.Println("[WebSocket] Ошибка десериализации результата:", err)
	}
	return err
}

// FillArgs якщо в RPC-методах передбачено *websocket.Conn, замінює аргумент
func (c *codec) FillArgs(arglist []reflect.Value) error {
	for i := 0; i < len(arglist); i++ {
		if _, ok := arglist[i].Interface().(*websocket.Conn); ok {
			arglist[i] = reflect.ValueOf(c.WS)
		}
	}
	return nil
}
*/

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
