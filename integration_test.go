package wsrpc_test

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/websocket"

	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
)

const testKey = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" // 32 'q'

// ServerService — сервис, который вызывает метод на клиенте
type ServerService struct{}

func (s *ServerService) CallClient(_ *struct{}, _ *struct{}, ep *wsrpc.Endpoint) error {
	log.Println("[Server] Клиент вызвал сервер, вызываем ClientFunc на клиенте")
	var reply struct{}
	return ep.Call("ClientService.ClientFunc", &struct{}{}, &reply)
}

// ClientService — сервис, который вызывается сервером
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

func TestBidirectionalRPC(t *testing.T) {
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Канал, через который HandlerFunc отдасть нам свой endpoint
	serverEPCh := make(chan *wsrpc.Endpoint, 1)

	// Поднимаем тестовый HTTP+WebSocket сервер
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Upgrade failed: %v", err)
		}

		// Создаем серверный endpoint и шлём его в main-гору
		registry := wsrpc.NewRegistry()
		registry.RegisterService(&ServerService{})
		ep, err := wetsock.NewEndpoint(registry, conn, testKey)
		if err != nil {
			t.Fatalf("NewEndpoint failed: %v", err)
		}
		serverEPCh <- ep

		// Запускаем Serve() для сервера
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Println("[Server] Начинаем Serve()")
			if err := ep.Serve(); err != nil && !isCloseErr(err) {
				t.Errorf("server Serve error: %v", err)
			}
			log.Println("[Server] Serve() завершился")
		}()
	}))
	defer s.Close()

	// Подключаем клиента
	wsURL := "ws" + s.URL[4:]

	// Настраиваем клиентский endpoint
	clientRegistry := wsrpc.NewRegistry()
	clientSvc := &ClientService{Done: done}
	clientRegistry.RegisterService(clientSvc)
	clientEP, err := wetsock.NewAutoEndpoint(clientRegistry, wsURL, http.Header{}, testKey)
	if err != nil {
		t.Fatalf("NewEndpoint (client) failed: %v", err)
	}

	// Запускаем Serve() для клиента
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("[Client] Начинаем Serve()")
		if err := clientEP.Serve(); err != nil && !isCloseErr(err) {
			t.Errorf("client Serve error: %v", err)
		}
		log.Println("[Client] Serve() завершился")
	}()

	// Получаем серверный endpoint из handler’а
	serverEP := <-serverEPCh

	// Делаем первый вызов: клиент → сервер → клиент
	var reply struct{}
	if err := clientEP.Call("ServerService.CallClient", &struct{}{}, &reply); err != nil {
		t.Fatalf("client.Call error: %v", err)
	}

	// Ждём, пока ClientService.ClientFunc закроет done
	<-done

	// Теперь мы завершаем оба endpoint’а в явном порядке
	if err := clientEP.Close(); err != nil {
		t.Errorf("client Close error: %v", err)
	}
	if err := serverEP.Close(); err != nil {
		t.Errorf("server Close error: %v", err)
	}

	// Ждём, пока оба Serve() закончатся
	wg.Wait()
}
