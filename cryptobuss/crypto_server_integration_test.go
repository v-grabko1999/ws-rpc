package cryptobuss_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/cryptobuss"
)

// --- допоміжні сервіси для теста ---

// ServerService розміщується на сервері; у тесті ми змусимо сервер викликати клієнта.
type ServerService struct{}

func (s *ServerService) CallClient(_ *struct{}, _ *struct{}, ep *wsrpc.Endpoint) error {
	log.Println("[Server] Клиент вызвал сервер, вызываем ClientFunc на клиенте")
	// Сервер викликає метод на клієнті
	var reply struct{}
	return ep.Call("ClientService.ClientFunc", &struct{}{}, &reply)
}

// ClientService розміщується на клієнті — закриває done коли викликаний.
type ClientService struct {
	Done chan struct{}
}

func (c *ClientService) ClientFunc(_ *struct{}, _ *struct{}) error {
	log.Println("[Client] Сервер вызвал ClientFunc, сигнализируем Done")
	close(c.Done)
	return nil
}

func isCloseErr(err error) bool {
	if err == io.EOF {
		return true
	}
	return websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway)
}

// --- власне тест ---

func TestIntegration_ServerAndClient_PublicAPI(t *testing.T) {
	var wg sync.WaitGroup

	// канал для отримання server endpoint з handler'а (щоб можемо його коректно закрити)
	serverEPCh := make(chan *wsrpc.Endpoint, 1)

	// канал для повідомлення про помилку клієнта
	clientErrCh := make(chan error, 1)

	// сигнал завершення від клієнтського сервісу
	done := make(chan struct{})

	// 1) генеруємо Ed25519 ключі (серверний підписний ключ)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key failed: %v", err)
	}
	serverPubB64 := base64.StdEncoding.EncodeToString(pub)

	// 2) готуємо ServerCfg
	serverCfg := &cryptobuss.ServerCfg{
		SignPriv: priv,
		KeyID:    "test-key-1",
		OnRegistry: func(reg *wsrpc.Registry) error {
			reg.RegisterService(&ServerService{})
			return nil
		},
		OnEndpoint: func(ep *wsrpc.Endpoint) error {
			// віддаємо endpoint назовні, щоб тест міг його закрити вкінці
			select {
			case serverEPCh <- ep:
			default:
			}

			// Запускаємо Serve() в горутині
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := ep.Serve(); err != nil && !isCloseErr(err) {
					t.Logf("[Server] Serve error: %v", err)
				}
			}()

			// Також запустимо фонову спробу викликати клієнтський метод —
			// робимо це з невеликими повторними спробами (щоб уникнути race)
			wg.Add(1)
			go func() {
				defer wg.Done()
				// чекаємо трохи для стабільності з'єднання
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					// Викликаємо ClientService.ClientFunc (якщо клієнт вже зареєстрував свій сервіс — викличеться)
					var reply struct{}
					err := ep.Call("ClientService.ClientFunc", &struct{}{}, &reply)
					if err == nil {
						// успіх — більше не намагаємось
						return
					}
					// не вдалось — зачекаємо і спробуємо ще
					time.Sleep(50 * time.Millisecond)
				}
				// якщо не вдалось — логнемо
				t.Logf("[Server] warning: could not call client method within timeout")
			}()

			return nil
		},
	}

	// 3) піднімаємо httptest сервер
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Викликаємо ваш public Server API всередині handler'а
		err := cryptobuss.Server(serverCfg, w, r)
		if err != nil {
			// Якщо Server повернув помилку — лог і завершення тесту
			t.Fatalf("cryptobuss.Server returned error: %v", err)
		}
	}))
	defer srv.Close()

	// 4) Підготуємо клієнтську конфігурацію
	clientCfg := &cryptobuss.ClientCfg{
		HttpHeaders:         map[string]string{},
		Services:            []interface{}{&ClientService{Done: done}},
		RpcServerURL:        srv.URL, // Client побудує ws://.../rpc сам
		ServerSignPubBase64: serverPubB64,
		OnHttpResponse:      nil,
	}

	// 5) Запустимо клієнт у горутині
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := cryptobuss.Client(clientCfg)
		// Client зазвичай завершується при cfg.Stop() — сюди повернеться nil або помилка
		clientErrCh <- err
	}()

	// Невелика пауза — даємо клієнту піднятися і встановити handshake (робоча страховка)
	time.Sleep(100 * time.Millisecond)

	// 6) Чекаємо сигналу від client service (сервер має викликати його через ep.Call)
	select {
	case <-done:
		// усе OK
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for client service to be called")
	}

	// 7) Коректно завершуємо клієнта і сервер
	// Спочатку закриваємо серверний endpoint (щоб client.Serve() повернувся)
	var serverEP *wsrpc.Endpoint
	select {
	case serverEP = <-serverEPCh:
		// якщо маємо endpoint — закриваємо його, це розірве з'єднання з клієнтом
		if serverEP != nil {
			if err := serverEP.Close(); err != nil {
				t.Logf("serverEP.Close error: %v", err)
			}
		}
	case <-time.After(500 * time.Millisecond):
		// якщо endpoint ми не отримали — закриємо сам httptest сервер, що також розірве коннекшени
		t.Log("server endpoint not received quickly; closing test server to force client disconnect")
		// srv.Close() викличе defer та розірве коннекшени
		// але оскільки srv вищезадекларований в тесті і буде закритий у defer,
		// тут можна додатково викликати srv.Close() тільки якщо доступно в скоупі.
	}

	// Тепер, коли серверна сторона розірвала з'єднання, client.Serve() має повернутися
	// і цикл Client() зможе обробити сигнал stopped. Тепер викликаємо Stop().
	// Stop() блокує до тих пір, поки в goroutine Client() не прочитає зі свого каналу.
	clientCfg.Stop()

	// 8) Чекаємо, поки client goroutine поверне результат
	select {
	case cerr := <-clientErrCh:
		if cerr != nil {
			t.Logf("cryptobuss.Client returned error: %v", cerr)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for Client to stop after server closed connection")
	}

	// 9) Зачекаємо завершення goroutine'ів, запущених у handler'і
	wg.Wait()
}
