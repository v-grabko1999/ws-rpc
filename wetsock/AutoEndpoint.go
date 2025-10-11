package wetsock

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	wsrpc "github.com/v-grabko1999/ws-rpc"
)

type AutoEndpoint struct {
	registry *wsrpc.Registry
	url      string
	header   http.Header
	key      string

	mu  sync.Mutex
	ep  *wsrpc.Endpoint
	ws  *websocket.Conn
	cls bool

	// для heartbeat та reconnect
	pingTicker  *time.Ticker
	reconnectCh chan struct{}
}

// NewAutoEndpoint створює AutoEndpoint, одразу підключається і запускає heartbeat
func NewAutoEndpoint(registry *wsrpc.Registry, url string, header http.Header, key string) (*AutoEndpoint, error) {
	ae := &AutoEndpoint{
		registry:    registry,
		url:         url,
		header:      header,
		key:         key,
		reconnectCh: make(chan struct{}, 1),
	}
	if err := ae.connect(); err != nil {
		return nil, err
	}
	// стартуємо heartbeat
	ae.pingTicker = time.NewTicker(pingInterval)
	go ae.heartbeatLoop()
	return ae, nil
}

// connect — dial + NewEndpoint
func (ae *AutoEndpoint) connect() error {
	ws, _, err := websocket.DefaultDialer.Dial(ae.url, ae.header)
	if err != nil {
		return fmt.Errorf("dial ws: %w", err)
	}
	ep, err := NewEndpoint(ae.registry, nil, ws, ae.key)
	if err != nil {
		ws.Close()
		return err
	}

	ae.mu.Lock()
	ae.ws = ws
	ae.ep = ep
	ae.mu.Unlock()
	return nil
}

// heartbeatLoop — пінгуємо й при помилці шлемо сигнал на reconnect
func (ae *AutoEndpoint) heartbeatLoop() {
	for {
		select {
		case <-ae.pingTicker.C:
			ae.mu.Lock()
			if ae.cls {
				ae.mu.Unlock()
				return
			}
			if err := ae.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Println("[AutoEndpoint] ping failed, reconnecting:", err)
				ae.triggerReconnect()
			}
			ae.mu.Unlock()
		case <-ae.reconnectCh:
			ae.doReconnect()
		}
	}
}

// triggerReconnect — ненав’язливо шле сигнал, щоб уникнути блокування
func (ae *AutoEndpoint) triggerReconnect() {
	select {
	case ae.reconnectCh <- struct{}{}:
	default:
	}
}

// doReconnect — експоненційний backoff
func (ae *AutoEndpoint) doReconnect() {
	ae.mu.Lock()
	if ae.cls {
		ae.mu.Unlock()
		return
	}
	ae.mu.Unlock()

	// закриваємо старий ep/ws
	ae.mu.Lock()
	_ = ae.ep.Close()
	_ = ae.ws.Close()
	ae.mu.Unlock()

	// цикл спроб
	for i := 0; i < reconnectMaxAttempts; i++ {
		backoff := reconnectBackoffBase * (1 << i)
		time.Sleep(backoff)
		log.Printf("[AutoEndpoint] reconnect attempt #%d", i+1)
		if err := ae.connect(); err != nil {
			log.Println("[AutoEndpoint] reconnect failed:", err)
			continue
		}
		log.Println("[AutoEndpoint] reconnect successful")
		return
	}
	log.Printf("[AutoEndpoint] could not reconnect after %d attempts", reconnectMaxAttempts)
}

// Serve делегує Serve() внутрішнього endpoint
func (ae *AutoEndpoint) Serve() error {
	for {
		ae.mu.Lock()
		ep := ae.ep
		ae.mu.Unlock()

		if ep == nil {
			return fmt.Errorf("no endpoint to serve")
		}
		err := ep.Serve()
		// якщо ми ініціювали закриття — виходимо
		ae.mu.Lock()
		if ae.cls {
			ae.mu.Unlock()
			return nil
		}
		ae.mu.Unlock()

		log.Println("[AutoEndpoint] Serve() exited with:", err, " — спробуємо reconnect")
		ae.doReconnect()
	}
}

// Call делегує виклик внутрішньому endpoint
func (ae *AutoEndpoint) Call(method string, args, reply interface{}) error {
	ae.mu.Lock()
	ep := ae.ep
	ae.mu.Unlock()
	return ep.Call(method, args, reply)
}

// Close коректно завершує heartbeat і endpoint
func (ae *AutoEndpoint) Close() error {
	ae.mu.Lock()
	ae.cls = true
	ae.mu.Unlock()

	ae.pingTicker.Stop()
	ae.triggerReconnect() // щоб heartbeatLoop завершився

	ae.mu.Lock()
	defer ae.mu.Unlock()
	if ae.ep != nil {
		return ae.ep.Close()
	}
	return nil
}
