package wsrpc

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Client представляет WebSocket-клиента
type Client struct {
	conn    *websocket.Conn
	wsURL   string
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	pingInt time.Duration
}

// NewClient создает WebSocket-клиента
func NewClient(wsURL string, headers http.Header, pingInterval int) (*Client, error) {
	dialer := websocket.DefaultDialer

	// Подключаемся к WebSocket-серверу
	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		// Обработка ответа от сервера
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusTooManyRequests:
				return nil, errors.New("превышено максимальное количество соединений")
			case http.StatusInternalServerError:
				return nil, errors.New("не удалось установить WebSocket-соединение")
			default:
				return nil, errors.New("ошибка соединения: " + resp.Status)
			}
		}
		return nil, err
	}

	// Создаем контекст для управления соединением
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		conn:    conn,
		wsURL:   wsURL,
		ctx:     ctx,
		cancel:  cancel,
		pingInt: time.Duration(pingInterval) * time.Second,
	}

	// Устанавливаем обработчик Pong-ответов
	client.conn.SetPongHandler(func(appData string) error {
		log.Println("Получен Pong от сервера")
		client.conn.SetReadDeadline(time.Now().Add(client.pingInt * 2)) // Обновляем таймаут
		return nil
	})

	// Запускаем Ping-поток
	go client.startPingLoop()

	return client, nil
}

// startPingLoop отправляет Ping каждые `pingInt` секунд
func (c *Client) startPingLoop() {
	ticker := time.NewTicker(c.pingInt)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			err := c.conn.WriteMessage(websocket.PingMessage, nil)
			c.mu.Unlock()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Println("Сервер закрыл соединение:", err)
					return
				}
				log.Println("Ошибка при отправке Ping:", err)
				c.Reconnect()
				return
			}
		case <-c.ctx.Done():
			log.Println("Ping-горутинa завершена")
			return
		}
	}
}

// Reconnect восстанавливает соединение в случае разрыва
func (c *Client) Reconnect() {
	log.Println("Попытка переподключения...")

	c.mu.Lock()
	defer c.mu.Unlock()

	// Закрываем текущее соединение
	if c.conn != nil {
		c.conn.Close()
	}

	// Повторные попытки подключения
	for i := 0; i < 5; i++ {
		conn, _, err := websocket.DefaultDialer.Dial(c.wsURL, nil)
		if err == nil {
			c.conn = conn
			log.Println("Соединение успешно восстановлено")
			go c.startPingLoop()
			return
		}

		log.Printf("Ошибка при переподключении (%d/5): %v", i+1, err)
		time.Sleep(2 * time.Second)
	}

	log.Println("Не удалось восстановить соединение")
}

// SendMessage отправляет сообщение серверу
func (c *Client) SendMessage(messageType int, message []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(messageType, message)
}

// ReadMessage читает сообщение от сервера
func (c *Client) ReadMessage() (int, []byte, error) {
	return c.conn.ReadMessage()
}

// Close закрывает WebSocket-соединение
func (c *Client) Close() {
	c.cancel() // Завершаем все горутины

	c.mu.Lock()
	defer c.mu.Unlock()

	// Отправляем CloseMessage перед закрытием
	err := c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		log.Println("Ошибка при отправке CloseMessage:", err)
	}

	// Ожидаем закрытия соединения перед принудительным разрывом
	time.Sleep(500 * time.Millisecond)

	// Закрываем WebSocket-соединение
	err = c.conn.Close()
	if err != nil {
		log.Println("Ошибка при закрытии WebSocket-соединения:", err)
	} else {
		log.Println("WebSocket-клиент корректно отключен")
	}
}
