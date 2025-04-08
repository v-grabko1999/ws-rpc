package wsrpc_test

import (
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	wsrpc "github.com/v-grabko1999/ws-rpc"
	"github.com/v-grabko1999/ws-rpc/wetsock"
)

const testKey = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" // 32 'q'

// Глобальные переменные
var stopServer sync.Once
var stopChan chan struct{}
var client *wsrpc.Endpoint

// ServerService - сервис, который вызывается клиентом
type ServerService struct{}

func (s *ServerService) CallClient(_ *struct{}, _ *struct{}, endpoint *wsrpc.Endpoint) error {
	log.Println("[Server] Клиент вызвал функцию на сервере")
	var reply struct{}

	err := endpoint.Call("ClientService.ClientFunc", &struct{}{}, &reply)
	if err != nil {
		log.Println("[Server] Ошибка вызова функции на клиенте:", err)
		return err
	}

	log.Println("[Server] Вызов функции на клиенте успешен")
	return nil
}

// ClientService - сервис, который вызывается сервером
type ClientService struct{}

func (c *ClientService) ClientFunc(_ *struct{}, _ *struct{}) error {
	log.Println("[Client] Сервер вызвал функцию на клиенте, начинаем закрытие...")

	// Даём серверу время обработать всё
	time.Sleep(100 * time.Millisecond)

	// Закрываем клиента перед сервером
	stopServer.Do(func() {
		log.Println("[Client] Закрываем клиентское соединение")
		_ = client.Close()

		log.Println("[Client] Клиент успешно завершил работу, отправляем сигнал серверу")
		stopChan <- struct{}{}
	})

	return nil
}

func TestBidirectionalRPC(t *testing.T) {
	log.Println("[Test] Запуск теста двустороннего RPC")

	stopChan = make(chan struct{})
	var wg sync.WaitGroup

	// Запуск сервера
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Ошибка обновления WebSocket: %v", err)
		}
		log.Println("[Server] WebSocket подключение установлено")

		// Реестр сервисов
		registry := wsrpc.NewRegistry()
		registry.RegisterService(&ServerService{})

		// Создаём RPC endpoint
		endpoint, err := wetsock.NewEndpoint(registry, conn, testKey)
		if err != nil {
			t.Fatal(err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Println("[Server] Ожидание сообщений...")
			if err := endpoint.Serve(); err != nil && err.Error() != "use of closed network connection" {
				log.Printf("[Server] Ошибка обработки запросов: %v", err)
			}
			log.Println("[Server] Сервер завершил работу")
		}()

		// Ждём закрытия сервера
		<-stopChan
		log.Println("[Server] Закрываем соединение")
		_ = endpoint.Close()
	}))
	defer s.Close()

	// Подключаем клиента к серверу
	wsURL := "ws" + s.URL[4:]
	log.Println("[Client] Подключение к серверу по WebSocket:", wsURL)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Ошибка подключения: %v", err)
	}

	// Регистрируем клиентский сервис
	clientRegistry := wsrpc.NewRegistry()
	clientRegistry.RegisterService(&ClientService{})

	client, err = wetsock.NewEndpoint(clientRegistry, conn, testKey)
	if err != nil {
		t.Fatal(err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("[Client] Клиент слушает запросы...")
		if err := client.Serve(); err != nil && err.Error() != "use of closed network connection" {
			log.Printf("[Client] Ошибка обработки запросов: %v", err)
		}
		log.Println("[Client] Клиент завершил работу")
	}()

	// Даём серверу и клиенту установиться
	time.Sleep(500 * time.Millisecond)

	// Клиент вызывает серверную функцию
	var reply struct{}
	err = client.Call("ServerService.CallClient", &struct{}{}, &reply)
	if err != nil {
		t.Fatalf("[Client] Ошибка вызова ServerService.CallClient: %v", err)
	}

	// Ждём завершения всех горутин
	wg.Wait()

	log.Println("[Test] Тест завершён успешно")
}
