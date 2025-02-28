package wsrpc

import (
	"fmt"
	"log"
)

// handleMessage обрабатывает сообщение в отдельной горутине
func (ser *ServerHandle) handleMessage(msgType int, msg []byte) (int, []byte, error) {
	log.Println("Получено сообщение:", string(msg))
	// Обрабатываем сообщение (эмуляция обработки)
	return msgType, []byte(fmt.Sprintf("Эхо: %s", msg)), nil
}
