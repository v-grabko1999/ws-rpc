package cryptobuss_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/cryptobuss"
)

// --- допоміжні сервіси для теста ---

// ServerService розміщується на сервері.
type ServerService struct{}

// Дозволений метод — тригер для клієнта.
func (s *ServerService) CallClient(_ *struct{}, _ *struct{}, ep *wsrpc.Endpoint) error {
	log.Println("[Server] Клиент вызвал сервер, вызываем ClientFunc на клиенте")
	var reply struct{}
	return ep.Call("ClientService.ClientFunc", &struct{}{}, &reply)
}

// Існуючий, але ЗАБОРОНЕНИЙ політикою метод.
// Він потрібен у реєстрі, щоб політика зрізала його ДО виконання.
func (s *ServerService) CallClientPerm(_ *struct{}, _ *struct{}, ep *wsrpc.Endpoint) error {
	log.Println("[Server] (forbidden) CallClientPerm був би виконаний, але має бути заблокований політикою")
	var reply struct{}
	// Навіть якщо тут щось є — до нас не повинні дійти через deny-list.
	return ep.Call("ClientService.ClientFunc", &struct{}{}, &reply)
}

// ClientService розміщується на клієнті — пробує заборонений виклик після сигналу від сервера.
type ClientService struct {
	Done         chan struct{}
	ForbiddenErr chan error
}

// Тепер маємо доступ до ендпойнта третьим параметром: ep *wsrpc.Endpoint
func (c *ClientService) ClientFunc(_ *struct{}, _ *struct{}, ep *wsrpc.Endpoint) error {
	log.Println("[Client] Сервер вызвал ClientFunc — пробуем заборонений виклик на сервері")

	// КЛІЄНТ намагається викликати на СЕРВЕРІ заборонений метод:
	var reply struct{}
	err := ep.Call("ServerService.CallClientPerm", &struct{}{}, &reply)

	// Повертаємо у тест отриману помилку:
	select {
	case c.ForbiddenErr <- err:
	default:
	}

	close(c.Done)
	return nil
}

// --- власне тест ---

func TestIntegration_ServerAndClient_PublicAPI(t *testing.T) {
	var wg sync.WaitGroup

	serverEPCh := make(chan *wsrpc.Endpoint, 1) // endpoint сервера назовні
	clientErrCh := make(chan error, 1)          // помилка/результат клієнта

	done := make(chan struct{})
	forbiddenErrCh := make(chan error, 1)

	// 1) Ключі
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key failed: %v", err)
	}
	serverPubB64 := base64.StdEncoding.EncodeToString(pub)

	// 2) ServerCfg з deny-list
	serverCfg := &cryptobuss.ServerCfg{
		SignPriv: priv,
		KeyID:    "test-key-1",

		OnRegistry: func(reg *wsrpc.Registry) error {
			reg.RegisterService(&ServerService{})
			return nil
		},
		OnEndpoint: func(r *http.Request, id string, ep *wsrpc.Endpoint) error {
			// Віддаємо endpoint у тест:
			select {
			case serverEPCh <- ep:
			default:
			}

			// Паралельно пробуємо викликати метод клієнта (щоб гарантовано спрацював ClientFunc)
			wg.Add(1)
			go func() {
				defer wg.Done()
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					var reply struct{}
					if err := ep.Call("ClientService.ClientFunc", &struct{}{}, &reply); err == nil {
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
				t.Logf("[Server] warning: could not call client method within timeout")
			}()
			return nil
		},
	}

	// 3) HTTP test server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := cryptobuss.Server(serverCfg, &wsrpc.Permission{
			Mode: wsrpc.PermissionDenyList,
			List: map[string]bool{
				"ServerService.CallClientPerm": true, // ЗАБОРОНЕНО
			},
		}, w, r); err != nil {
			t.Fatalf("cryptobuss.Server returned error: %v", err)
		}
	}))
	defer srv.Close()

	// 4) ClientCfg
	clientCfg := &cryptobuss.ClientCfg{
		HttpHeaders:         map[string]string{},
		Services:            []interface{}{&ClientService{Done: done, ForbiddenErr: forbiddenErrCh}},
		RpcServerURL:        srv.URL,
		ServerSignPubBase64: serverPubB64,
		OnHttpResponse:      nil,
	}

	// 5) Старт клієнта
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := cryptobuss.Client("test-key-1", clientCfg)
		clientErrCh <- err
	}()

	// Невелика пауза на handshake
	time.Sleep(100 * time.Millisecond)

	// 6) Чекаємо, поки клієнт відпрацює ClientFunc і спробує заборонений виклик
	select {
	case <-done:
		// ок
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for client service to be called")
	}

	// 6.1) Читаємо результат спроби забороненого виклику
	select {
	case ferr := <-forbiddenErrCh:
		if ferr == nil {
			t.Errorf("очікувалась помилка доступу при виклику ServerService.CallClientPerm, але помилки немає")
		} else {
			em := strings.ToLower(ferr.Error())
			// Дозволяємо кілька узгоджених формулювань помилки
			if !(strings.Contains(em, "forbidden") ||
				strings.Contains(em, "not permitted") ||
				strings.Contains(em, "permission")) {
				t.Errorf("неочікуваний тип помилки для забороненого виклику: %v", ferr)
			} else {
				t.Logf("заборонений виклик повернув очікувану помилку: %v", ferr)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting forbidden call result from client")
	}

	// 7) Коректне завершення: один раз отримуємо endpoint та закриваємо
	var serverEP *wsrpc.Endpoint
	select {
	case serverEP = <-serverEPCh:
		if serverEP != nil {
			if err := serverEP.Close(); err != nil {
				t.Logf("serverEP.Close error: %v", err)
			}
		}
	case <-time.After(500 * time.Millisecond):
		t.Log("server endpoint not received quickly; closing test server to force client disconnect")
	}

	// Невелика пауза, щоб клієнт вийшов із Serve()
	time.Sleep(50 * time.Millisecond)

	// Зупинка клієнта
	clientCfg.Stop()

	// 8) Чекаємо завершення клієнта
	select {
	case cerr := <-clientErrCh:
		if cerr != nil {
			t.Logf("cryptobuss.Client returned error: %v", cerr)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for Client to stop after server closed connection")
	}

	// 9) Дочікуємося бекграундних горутин
	wg.Wait()
}
