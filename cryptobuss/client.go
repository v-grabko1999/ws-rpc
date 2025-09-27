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

	// Пін (base64) Ed25519 публічного ключа сервера
	ServerSignPubBase64 string

	// ---- НОВЕ: керування перепідключеннями ----
	// Скільки разів поспіль можна намагатись підключитись після розриву (0 = безліміт)
	MaxReconnects int

	// Загальний бюджет часу на перепідключення після одного розриву (0 = безліміт)
	// Вимірюється з моменту першої невдалої спроби.
	TotalRetryTimeout time.Duration

	// Базова й максимальна затримки backoff (якщо 0 — використовуються дефолти 500ms/30s)
	BaseDelay time.Duration
	MaxDelay  time.Duration

	// Частка джиттера [0..1], напр. 0.5 означає ±50% випадковості (якщо 0 — дефолт 0.5)
	JitterFrac float64

	// Колбеки (необов'язкові)
	OnReconnectAttempt func(attempt int, sleep time.Duration, lastErr error)
	OnConnected        func()                                          // коли з’єднання встановлено
	OnDisconnected     func(err error)                                 // коли Serve() завершився
	OnGiveUp           func(reason string, attempt int, lastErr error) // коли припиняємо спроби
}

// обмеження shift’ів, дефолти, джиттер і «стеля»
func (cfg *ClientCfg) nextBackoff(attempt int) time.Duration {
	base := cfg.BaseDelay
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	maxd := cfg.MaxDelay
	if maxd <= 0 {
		maxd = 30 * time.Second
	}
	// експоненційно, але з безпечною «стелею»
	// 1<<attempt може переповнитись — обмежимося поки sleep < maxd
	sleep := base
	for i := 0; i < attempt; i++ {
		sleep *= 2
		if sleep >= maxd {
			sleep = maxd
			break
		}
	}
	jf := cfg.JitterFrac
	if jf <= 0 || jf > 1 {
		jf = 0.5
	}
	// джиттер у межах ±jf
	// напр., jf=0.5 → діапазон [0.5..1.5]*sleep
	delta := time.Duration(float64(sleep) * jf)
	low := sleep - delta
	high := sleep + delta
	if high <= low {
		return sleep
	}
	// rand у вже засіяному mrand
	jitter := time.Duration(mrand.Int63n(int64(high-low))) + low
	if jitter > maxd {
		jitter = maxd
	}
	if jitter < 0 {
		jitter = 0
	}
	return jitter
}

func Client(cfg *ClientCfg) error {
	if cfg == nil || cfg.ServerSignPubBase64 == "" {
		return errors.New("client config: ServerSignPubBase64 required")
	}
	cfg.stopped = make(chan struct{}, 1)
	mrand.Seed(time.Now().UnixNano())

	registry := wsrpc.NewRegistry()
	for _, s := range cfg.Services {
		registry.RegisterService(s)
	}

	h := http.Header{}
	for k, v := range cfg.HttpHeaders {
		h.Set(k, v)
	}

	wsScheme := "ws"
	if strings.HasPrefix(cfg.RpcServerURL, "https://") {
		wsScheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s/rpc", wsScheme, strings.TrimPrefix(strings.TrimPrefix(cfg.RpcServerURL, "http://"), "https://"))

	attempt := 0
	var deadline time.Time
	var lastErr error

	// локальний хелпер очікування зі всіма перевірками
	waitOrStop := func(sleep time.Duration) bool {
		if !deadline.IsZero() && time.Now().Add(sleep).After(deadline) {
			// не встигаємо за бюджетом
			if cfg.OnGiveUp != nil {
				cfg.OnGiveUp("total-timeout", attempt, lastErr)
			}
			return false
		}
		select {
		case <-cfg.stopped:
			if cfg.OnGiveUp != nil {
				cfg.OnGiveUp("stopped", attempt, lastErr)
			}
			return false
		case <-time.After(sleep):
			return true
		}
	}

	for {
		// «м’який» вихід
		select {
		case <-cfg.stopped:
			return nil
		default:
		}

		log.Println("[WebSocket] Попытка подключения к серверу...")

		conn, res, err := websocket.DefaultDialer.Dial(wsURL, h)
		if err != nil {
			lastErr = err
			// стартуємо вікно TotalRetryTimeout з першого фейлу
			if attempt == 0 && cfg.TotalRetryTimeout > 0 && deadline.IsZero() {
				deadline = time.Now().Add(cfg.TotalRetryTimeout)
			}
			// ліміт спроб?
			if cfg.MaxReconnects > 0 && attempt >= cfg.MaxReconnects {
				if cfg.OnGiveUp != nil {
					cfg.OnGiveUp("max-reconnects", attempt, lastErr)
				}
				return fmt.Errorf("dial failed: %w (max reconnects reached)", err)
			}
			sleep := cfg.nextBackoff(attempt)
			if cfg.OnReconnectAttempt != nil {
				cfg.OnReconnectAttempt(attempt+1, sleep, lastErr)
			}
			attempt++
			if !waitOrStop(sleep) {
				return nil
			}
			continue
		}

		// dial ok → скидаємо лічильники
		attempt = 0
		deadline = time.Time{}

		if cfg.OnHttpResponse != nil {
			if err = cfg.OnHttpResponse(res); err != nil {
				lastErr = err
				_ = conn.Close()
				if cfg.MaxReconnects > 0 && attempt >= cfg.MaxReconnects {
					if cfg.OnGiveUp != nil {
						cfg.OnGiveUp("max-reconnects", attempt, lastErr)
					}
					return fmt.Errorf("OnHttpResponse: %w", err)
				}
				sleep := cfg.nextBackoff(attempt)
				if cfg.OnReconnectAttempt != nil {
					cfg.OnReconnectAttempt(attempt+1, sleep, lastErr)
				}
				attempt++
				if !waitOrStop(sleep) {
					return nil
				}
				continue
			}
		}

		sessionKey, err := performClientHandshake(conn, cfg.ServerSignPubBase64, "key-id")
		if err != nil || len(sessionKey) != 32 {
			if err == nil {
				err = fmt.Errorf("invalid session key length: %d", len(sessionKey))
			}
			lastErr = err
			_ = conn.Close()
			if attempt == 0 && cfg.TotalRetryTimeout > 0 && deadline.IsZero() {
				deadline = time.Now().Add(cfg.TotalRetryTimeout)
			}
			if cfg.MaxReconnects > 0 && attempt >= cfg.MaxReconnects {
				if cfg.OnGiveUp != nil {
					cfg.OnGiveUp("max-reconnects", attempt, lastErr)
				}
				return fmt.Errorf("handshake failed: %w", err)
			}
			sleep := cfg.nextBackoff(attempt)
			if cfg.OnReconnectAttempt != nil {
				cfg.OnReconnectAttempt(attempt+1, sleep, lastErr)
			}
			attempt++
			if !waitOrStop(sleep) {
				return nil
			}
			continue
		}

		endpoint, err := wetsock.NewEndpoint(registry, conn, string(sessionKey))
		if err != nil {
			lastErr = err
			_ = conn.Close()
			if attempt == 0 && cfg.TotalRetryTimeout > 0 && deadline.IsZero() {
				deadline = time.Now().Add(cfg.TotalRetryTimeout)
			}
			if cfg.MaxReconnects > 0 && attempt >= cfg.MaxReconnects {
				if cfg.OnGiveUp != nil {
					cfg.OnGiveUp("max-reconnects", attempt, lastErr)
				}
				return fmt.Errorf("NewEndpoint: %w", err)
			}
			sleep := cfg.nextBackoff(attempt)
			if cfg.OnReconnectAttempt != nil {
				cfg.OnReconnectAttempt(attempt+1, sleep, lastErr)
			}
			attempt++
			if !waitOrStop(sleep) {
				return nil
			}
			continue
		}

		if cfg.OnConnected != nil {
			cfg.OnConnected()
		}

		// Блокуємось у Serve() до розриву
		if err := endpoint.Serve(); err != nil {
			lastErr = err
			if cfg.OnDisconnected != nil {
				cfg.OnDisconnected(err)
			}
		}

		// після розриву — пауза між сесіями (не backoff, а м’який «cooldown»)
		cooldown := 1*time.Second + time.Duration(mrand.Int63n(int64(1000*time.Millisecond)))
		select {
		case <-cfg.stopped:
			_ = endpoint.Close()
			return nil
		case <-time.After(cooldown):
		}

		// при переході до нового циклу перепідключень стартуємо бюджет часу
		attempt = 0
		deadline = time.Time{}
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
