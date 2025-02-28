package wsrpc_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	wsrpc "github.com/v-grabko1999/ws-rpc"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

// Тест WebSocket-сервера и клиента
func TestWebSocketConnection(t *testing.T) {
	wsSer, err := wsrpc.NewServer(&wsrpc.ServerConfig{
		PingInterval: 5,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Создаем тестовый HTTP-сервер
	server := httptest.NewServer(wsSer)
	defer server.Close()

	// Преобразуем тестовый сервер в WebSocket-адрес
	wsURL := "ws" + server.URL[len("http"):]

	cl, err := wsrpc.NewClient(wsURL, make(http.Header), 5)
	if err != nil {
		t.Fatal(err)
	}

	assert.NoError(t, err, "Ошибка при подключении к WebSocket-серверу")
	defer cl.Close()

	// Отправляем сообщение
	sendMsg := "Привет, WebSocket!"
	err = cl.SendMessage(websocket.TextMessage, []byte(sendMsg))
	assert.NoError(t, err, "Ошибка при отправке сообщения")

	// Читаем ответ от сервера
	_, recvMsg, err := cl.ReadMessage()
	assert.NoError(t, err, "Ошибка при получении сообщения")
	expectedResponse := "Эхо: " + sendMsg
	assert.Equal(t, expectedResponse, string(recvMsg), "Полученное сообщение не совпадает с отправленным")

}
