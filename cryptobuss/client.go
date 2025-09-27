package cryptobuss

import (
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
)

type ClientCfg struct {
	HttpHeaders    map[string]string
	Services       []interface{}
	RpcServerURL   string
	OnHttpResponse func(*http.Response) error
	stopped        chan struct{}
	// Пін (base64) публічного Ed25519 ключа сервера (видаєте клієнтам вручну)
	ServerSignPubBase64 string
}

func Client(cfg *ClientCfg) error {
	// Обов'язковий pinned pub key
	if cfg == nil || cfg.ServerSignPubBase64 == "" {
		return errors.New("client config: ServerSignPubBase64 required")
	}

	// робимо stopped неблокуючим — Stop() не буде блокуватись
	cfg.stopped = make(chan struct{}, 1)

	// seed для джиттера backoff
	mrand.Seed(time.Now().UnixNano())

	// Создаем и регистрируем RPC сервис
	registry := wsrpc.NewRegistry()
	if len(cfg.Services) > 0 {
		for _, service := range cfg.Services {
			registry.RegisterService(service)
		}
	} else {
		log.Println("[WebSocket] Внимание: нет зарегистрированных сервисов!")
	}

	h := http.Header{}
	for key, val := range cfg.HttpHeaders {
		h.Set(key, val)
	}

	wsScheme := "ws"
	if strings.HasPrefix(cfg.RpcServerURL, "https://") {
		wsScheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s/rpc", wsScheme, strings.TrimPrefix(strings.TrimPrefix(cfg.RpcServerURL, "http://"), "https://"))

	// параметры переподключения
	baseDelay := 500 * time.Millisecond
	maxDelay := 30 * time.Second
	attempt := 0

	for {
		// если нам приказали остановиться — выходим
		select {
		case <-cfg.stopped:
			log.Println("[WebSocket] Остановка WebSocket-переподключений")
			return nil
		default:
		}

		log.Println("[WebSocket] Попытка подключения к серверу...")

		conn, res, err := websocket.DefaultDialer.Dial(wsURL, h)
		if err != nil {
			// Dial failed — retry with backoff + jitter
			log.Println("[WebSocket] Dial error:", err)
			// compute backoff (exponential)
			sleep := baseDelay * (1 << attempt)
			if sleep > maxDelay {
				sleep = maxDelay
			}
			// jitter: [0, sleep/2)
			j := time.Duration(mrand.Int63n(int64(sleep / 2)))
			sleep = sleep + j
			attempt++
			// wait or exit if stopped
			select {
			case <-cfg.stopped:
				return nil
			case <-time.After(sleep):
				continue
			}
		}

		// успешный dial — сбрасываем попытки
		attempt = 0

		if cfg.OnHttpResponse != nil {
			if err = cfg.OnHttpResponse(res); err != nil {
				// OnHttpResponse может вернуть ошибку — закрываем и пробуем снова
				log.Println("[WebSocket] OnHttpResponse error:", err)
				conn.Close()
				// небольшой backoff перед новой попыткой
				sleep := baseDelay + time.Duration(mrand.Int63n(int64(baseDelay)))
				select {
				case <-cfg.stopped:
					return nil
				case <-time.After(sleep):
					continue
				}
			}
		}

		// Выполняем handshake (перед созданием wetsock.Endpoint)
		sessionKey, err := performClientHandshake(conn, cfg.ServerSignPubBase64)
		if err != nil {
			log.Println("[KeyExchange] handshake failed:", err)
			conn.Close()
			// backoff перед повторной попыткой
			sleep := baseDelay + time.Duration(mrand.Int63n(int64(baseDelay)))
			select {
			case <-cfg.stopped:
				return nil
			case <-time.After(sleep):
				continue
			}
		}
		if len(sessionKey) != 32 {
			log.Println("[KeyExchange] invalid session key length:", len(sessionKey))
			conn.Close()
			sleep := baseDelay + time.Duration(mrand.Int63n(int64(baseDelay)))
			select {
			case <-cfg.stopped:
				return nil
			case <-time.After(sleep):
				continue
			}
		}

		// Создаем RPC-эндпоинт с полученным sessionKey
		endpoint, err := wetsock.NewEndpoint(registry, conn, string(sessionKey))
		if err != nil {
			// не создался endpoint — закрываем и пробуем снова
			log.Println("[WebSocket NewEndpoint] Внимание:", err)
			conn.Close()
			sleep := baseDelay + time.Duration(mrand.Int63n(int64(baseDelay)))
			select {
			case <-cfg.stopped:
				return nil
			case <-time.After(sleep):
				continue
			}
		}

		// Успешно подключились и создали endpoint — начинаем Serve()
		if err := endpoint.Serve(); err != nil {
			log.Println("[WebSocket] Соединение закрыто:", err)
		}

		// Когда Serve() завершился — либо соединение закрылось, либо произошла ошибка.
		// Делаем короткую паузу и переподключаемся (если не остановлены).
		select {
		case <-cfg.stopped:
			// попытка аккуратно закрыть endpoint (если еще не закрыт)
			_ = endpoint.Close()
			return nil
		default:
		}
		// небольшой backoff между сессиями (чтобы не спамить при мгновенных провалах)
		sleep := 1*time.Second + time.Duration(mrand.Int63n(int64(1000*time.Millisecond)))
		select {
		case <-cfg.stopped:
			_ = endpoint.Close()
			return nil
		case <-time.After(sleep):
			// loop продолжится и попробуем переподключиться
		}
	}
}

func (cfg *ClientCfg) Stop() {
	// non-blocking stop so callers don't hang if channel already has a value
	if cfg == nil || cfg.stopped == nil {
		return
	}
	select {
	case cfg.stopped <- struct{}{}:
	default:
	}
}
