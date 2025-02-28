package wetsock

import (
	"encoding/json"
	"errors"
	"log"
	"reflect"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	wsrpc "github.com/v-grabko1999/ws-rpc"
)

type codec struct {
	WS        *websocket.Conn
	sendChan  chan *wsrpc.Message // Буфер для отправки сообщений
	mu        sync.Mutex          // Защита от гонок при записи в WebSocket
	closeOnce sync.Once           // Гарантия однократного закрытия
	wg        sync.WaitGroup      // Гарантия отправки всех сообщений перед закрытием
	closing   bool                // Флаг закрытия соединения
}

// jsonMessage используется для десериализации сообщений
type jsonMessage struct {
	ID     uint64          `json:"id,string,omitempty"`
	Func   string          `json:"fn,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *wsrpc.Error    `json:"error"`
}

// ReadMessage читает JSON-сообщение из WebSocket
func (c *codec) ReadMessage(msg *wsrpc.Message) error {
	var jm jsonMessage
	err := c.WS.ReadJSON(&jm)

	if err != nil {
		// Проверяем код ошибки WebSocket закрытия
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			log.Println("[WebSocket] Соединение закрыто:", err)
			return err
		}
		log.Println("[WebSocket] Ошибка чтения сообщения:", err)
		return err
	}

	// Заполняем структуру сообщения
	msg.ID = jm.ID
	msg.Func = jm.Func
	msg.Args = jm.Args
	msg.Result = jm.Result
	msg.Error = jm.Error
	return nil
}

// WriteMessage отправляет сообщение в `sendChan`, но не принимает новые после закрытия
func (c *codec) WriteMessage(msg *wsrpc.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closing {
		log.Println("[WebSocket] Попытка отправки сообщения после закрытия соединения!")
		return errors.New("соединение закрывается, отправка невозможна")
	}

	// Добавляем сообщение в очередь и увеличиваем счетчик отправок
	c.wg.Add(1)
	select {
	case c.sendChan <- msg:
		return nil
	case <-time.After(2 * time.Second): // Таймаут на отправку
		log.Println("[WebSocket] Таймаут отправки сообщения!")
		c.wg.Done() // Сбрасываем счетчик, так как сообщение не отправлено
		return errors.New("таймаут отправки сообщения")
	}
}

// sendLoop - горутина, отправляющая сообщения из `sendChan`
func (c *codec) sendLoop() {
	for msg := range c.sendChan {
		c.mu.Lock()
		err := c.WS.WriteJSON(msg)
		c.mu.Unlock()

		if err != nil {
			log.Println("[WebSocket] Ошибка при отправке сообщения:", err)
			break
		}
		// Отмечаем, что сообщение успешно отправлено
		c.wg.Done()
	}
}

// Close корректно завершает WebSocket-соединение
func (c *codec) Close() error {
	var err error

	c.closeOnce.Do(func() {
		log.Println("[WebSocket] Начато закрытие соединения...")

		// Блокируем новые отправки
		c.mu.Lock()
		c.closing = true
		c.mu.Unlock()

		// Дожидаемся, пока все сообщения из очереди будут отправлены
		log.Println("[WebSocket] Ожидание завершения всех отправок...")
		c.wg.Wait()

		// Отправляем CloseMessage перед закрытием
		closeMessage := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Закрытие соединения")
		err = c.WS.WriteMessage(websocket.CloseMessage, closeMessage)
		if err != nil {
			log.Println("[WebSocket] Ошибка при отправке CloseMessage:", err)
		}

		// Даем немного времени перед разрывом соединения
		time.Sleep(100 * time.Millisecond)

		// Закрываем WebSocket-соединение
		err = c.WS.Close()
		if err != nil {
			log.Println("[WebSocket] Ошибка при закрытии WebSocket:", err)
		} else {
			log.Println("[WebSocket] Клиент успешно отключен")
		}

		// Закрываем канал отправки
		close(c.sendChan)
	})
	return err
}

// UnmarshalArgs десериализует аргументы RPC-вызова
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

// UnmarshalResult десериализует результат RPC-вызова
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

// FillArgs заполняет аргументы вызова, если требуется передать WebSocket-соединение
func (c *codec) FillArgs(arglist []reflect.Value) error {
	for i := 0; i < len(arglist); i++ {
		if _, ok := arglist[i].Interface().(*websocket.Conn); ok {
			arglist[i] = reflect.ValueOf(c.WS)
		}
	}
	return nil
}

// NewCodec создает новый экземпляр кодека с WebSocket-соединением
func NewCodec(ws *websocket.Conn) *codec {
	c := &codec{
		WS:       ws,
		sendChan: make(chan *wsrpc.Message, 100), // Буфер на 100 сообщений
	}

	// Запускаем горутину для обработки отправки сообщений
	go c.sendLoop()

	return c
}

// NewEndpoint создает новый Endpoint для WebSocket
func NewEndpoint(registry *wsrpc.Registry, ws *websocket.Conn) *wsrpc.Endpoint {
	c := NewCodec(ws)
	e := wsrpc.NewEndpoint(c, registry)
	return e
}
