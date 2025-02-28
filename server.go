package wsrpc

import (
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Server представляет WebSocket-сервер
type ServerHandle struct {
	upgrader    websocket.Upgrader
	cfg         ServerConfig
	activeConns int32
}

type ServerConfig struct {
	PingInterval int
	MaxConns     int32
	Debug        bool
}

func (cfg *ServerConfig) SetDefault() ServerConfig {
	cop := *cfg
	if cop.PingInterval == 0 {
		cop.PingInterval = 30
	}

	if cop.MaxConns == 0 {
		cop.MaxConns = 1
	}

	return cop
}

// NewServer создает новый WebSocket-сервер
func NewServer(cfg *ServerConfig) (*ServerHandle, error) {
	return &ServerHandle{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Разрешаем соединения от любого клиента
			},
		},
		cfg: cfg.SetDefault(), // Период пинга клиента
	}, nil
}

// ServeHTTP обрабатывает WebSocket-соединение
func (ser *ServerHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Проверяем лимит подключений перед апгрейдом WebSocket
	if atomic.LoadInt32(&ser.activeConns) >= ser.cfg.MaxConns {
		http.Error(w, "Превышено максимальное количество соединений", http.StatusTooManyRequests)
		log.Println("Превышено максимальное количество соединений")
		return
	}

	conn, err := ser.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка при обновлении соединения:", err)
		http.Error(w, "Не удалось установить WebSocket-соединение", http.StatusInternalServerError)
		return
	}

	atomic.AddInt32(&ser.activeConns, 1)
	defer func() {
		atomic.AddInt32(&ser.activeConns, -1)
		conn.Close()
	}()

	conn.SetReadDeadline(time.Now().Add(time.Duration(ser.cfg.PingInterval) * 2 * time.Second))
	conn.SetPongHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(time.Duration(ser.cfg.PingInterval) * 2 * time.Second))
		return nil
	})

	// Канал для остановки пинг-горутины
	stopPing := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Println("Паника в обработке сообщения:", r)
			}
		}()
		ser.pingClient(conn, stopPing)
	}()

	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			// Проверяем код ошибки WebSocket закрытия
			if closeErr, ok := err.(*websocket.CloseError); ok {
				switch closeErr.Code {
				case websocket.CloseNormalClosure, websocket.CloseGoingAway:
					log.Println("Соединение закрыто корректно:", closeErr)
				default:
					log.Println("Неожиданное закрытие соединения:", closeErr)
				}
			} else {
				log.Println("Ошибка при чтении сообщения:", err)
			}
			break
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			code, res, err := ser.handleMessage(messageType, msg)
			if err != nil {
				log.Println(err)
				return
			}
			err = conn.WriteMessage(code, res)
			if err != nil {
				log.Println("Ошибка при отправке сообщения:", err)
			}
		}()
	}

	close(stopPing)
	wg.Wait()
}

// pingClient отправляет Ping-сообщения клиенту каждые ser.pingInt секунд
func (ser *ServerHandle) pingClient(conn *websocket.Conn, stop chan struct{}) {
	ticker := time.NewTicker(time.Duration(ser.cfg.PingInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if ser.cfg.Debug {
				log.Println("Отправка Ping-сообщения клиенту")
			}
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Println("Ошибка при отправке Ping:", err)
				return
			}
		case <-stop:
			return
		}
	}
}
