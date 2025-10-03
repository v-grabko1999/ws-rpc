package wetsock

import (
	"crypto/cipher"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ----------------------------------------------------------------------------
// Наш розширений codec
// ----------------------------------------------------------------------------

type codec struct {
	WS        *websocket.Conn
	sendChan  chan []byte // Зверніть увагу: зберігаємо зашифровані дані ([]byte)
	mu        sync.Mutex
	closeOnce sync.Once
	wg        sync.WaitGroup
	closing   bool

	heartbeatDone chan struct{} // канал для зупинки heartbeat

	// Поля для AES-GCM
	block cipher.Block
	gcm   cipher.AEAD
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
		err := c.WS.WriteMessage(websocket.BinaryMessage, payload)
		c.mu.Unlock()

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

func (c *codec) startHeartbeat() {

	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	// Встановлюємо ReadDeadline і обробник PONG
	c.WS.SetReadDeadline(time.Now().Add(pongWait))
	c.WS.SetPongHandler(func(appData string) error {
		return c.WS.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		select {
		case <-ticker.C:
			// синхронізуємо всі WriteControl через mu
			c.mu.Lock()
			c.WS.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.WS.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait)); err != nil {
				log.Println("[WebSocket] Не вдалося відправити PING:", err)
				c.mu.Unlock()
				return
			}
			c.mu.Unlock()
		case <-c.heartbeatDone:
			return
		}
	}
}

// ----------------------------------------------------------------------------
// Close: зупиняємо heartbeat, зачекаємо назавершення sendLoop і закриваємо з’єднання
// ----------------------------------------------------------------------------
func (c *codec) Close() error {
	var closeErr error

	c.closeOnce.Do(func() {
		log.Println("[WebSocket] Начато закрытие соединения...")

		// Забороняємо нові надсилання
		c.mu.Lock()
		c.closing = true
		c.mu.Unlock()

		// Зупиняємо heartbeat
		close(c.heartbeatDone)

		// Закриваємо канал sendChan, щоб завершився sendLoop
		close(c.sendChan)

		// Чекаємо, поки всі pending sendLoop завершаться
		log.Println("[WebSocket] Ожидание завершения всех отправок...")
		c.wg.Wait()

		// Відправляємо CloseMessage
		closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Закрытие соединения")
		if err := c.WS.WriteMessage(websocket.CloseMessage, closeMsg); err != nil {
			log.Println("[WebSocket] Ошибка при отправке CloseMessage:", err)
			closeErr = err
		}

		// Невелика пауза для надійності
		time.Sleep(100 * time.Millisecond)

		// І нарешті — закриваємо сокет
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
