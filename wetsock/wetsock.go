package wetsock

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"log"
	"reflect"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	wsrpc "github.com/v-grabko1999/ws-rpc"
)

// ----------------------------------------------------------------------------
// Допоміжні структури
// ----------------------------------------------------------------------------

// jsonMessage використовується для первинної десеріалізації після дешифрування
type jsonMessage struct {
	ID     uint64          `json:"id,string,omitempty"`
	Func   string          `json:"fn,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *wsrpc.Error    `json:"error"`
}

// ----------------------------------------------------------------------------
// Наш розширений codec
// ----------------------------------------------------------------------------

type codec struct {
	WS        *websocket.Conn
	sendChan  chan *[]byte // Зверніть увагу: зберігаємо зашифровані дані ([]byte)
	mu        sync.Mutex
	closeOnce sync.Once
	wg        sync.WaitGroup
	closing   bool

	// Поля для AES-GCM
	block cipher.Block
	gcm   cipher.AEAD
}

// ----------------------------------------------------------------------------
// Методи, що вимагає wsrpc.Codec
// ----------------------------------------------------------------------------

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

	// Гарантируем возврат в пул в любой ветке
	defer func() {
		*decryptedBufPtr = (*decryptedBufPtr)[:0]
		decryptPool.Put(decryptedBufPtr)
	}()

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
	case <-time.After(2 * time.Second):
		c.wg.Done()
		log.Println("[WebSocket] Таймаут отправки сообщения!")
		return errors.New("таймаут отправки сообщения")
	}

}

// ----------------------------------------------------------------------------
// sendLoop: відправляємо з каналу зашифрований payload
// ----------------------------------------------------------------------------
func (c *codec) sendLoop() {
	for {
		payload, ok := <-c.sendChan
		if !ok {
			// Канал закритий — завершуємо sendLoop
			return
		}

		c.mu.Lock()
		err := c.WS.WriteMessage(websocket.BinaryMessage, *payload)
		c.mu.Unlock()

		bufPool.Put(payload)
		// Завжди відмічаємо завершення відправки (успішної чи ні)
		c.wg.Done()

		if err != nil {
			log.Println("[WebSocket] Ошибка при отправке сообщения:", err)
			// Після помилки дренуємо решту, щоб уникнути дедлоку
			for range c.sendChan {
				c.wg.Done()
			}
			return
		}
	}
}

func (c *codec) Close() error {
	var closeErr error

	c.closeOnce.Do(func() {
		log.Println("[WebSocket] Начато закрытие соединения...")

		// Забороняємо нові надсилання
		c.mu.Lock()
		c.closing = true
		c.mu.Unlock()

		// Закриваємо канал, щоб sendLoop почав дренувати / завершуватися
		close(c.sendChan)

		// Чекаємо, поки всі відправки (і дренування) завершаться
		log.Println("[WebSocket] Ожидание завершения всех отправок...")
		c.wg.Wait()

		// Відправляємо фрейм закриття
		closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Закрытие соединения")
		if err := c.WS.WriteMessage(websocket.CloseMessage, closeMsg); err != nil {
			log.Println("[WebSocket] Ошибка при отправке CloseMessage:", err)
			closeErr = err
		}

		// Невелика затримка для надійності
		time.Sleep(100 * time.Millisecond)

		// І нарешті — закриваємо сам WebSocket-зʼєднання
		if err := c.WS.Close(); err != nil {
			log.Println("[WebSocket] Ошибка при закрытии WebSocket:", err)
			if closeErr == nil {
				closeErr = err
			}
		} else {
			log.Println("[WebSocket] Клиент успешно отключен")
		}
	})

	return closeErr
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

// ----------------------------------------------------------------------------
// Фабрика для створення зашифрованого codec
// ----------------------------------------------------------------------------

// NewCodec створює codec, приймаючи ключ як рядок
func NewCodec(ws *websocket.Conn, keyString string) (*codec, error) {
	// Припустимо, що нам потрібні рівно 32 байти (AES-256).
	key := []byte(keyString)
	if len(key) != 32 {
		return nil, errors.New("ключ повинен мати 32 байти довжини (AES-256)")
	}

	block, gcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}

	c := &codec{
		WS:       ws,
		sendChan: make(chan *[]byte, 100),
		block:    block,
		gcm:      gcm,
	}
	// Запускаємо горутину відправлення
	go c.sendLoop()

	return c, nil
}

func newAESGCM(key []byte) (cipher.Block, cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return block, gcm, nil
}

// NewEndpoint створює Endpoint для WebSocket з увімкненим шифруванням
func NewEndpoint(registry *wsrpc.Registry, ws *websocket.Conn, keyString string) (*wsrpc.Endpoint, error) {
	c, err := NewCodec(ws, keyString)
	if err != nil {
		return nil, err
	}
	e := wsrpc.NewEndpoint(c, registry)
	return e, nil
}
