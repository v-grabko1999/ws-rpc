package wetsock

import (
	crand "crypto/rand"
	"math/big"
	"time"
)

const (
	//WriteMessage
	MaxPad       = 128
	TimeOutWrite = 5
	//NewCodec
	SendChanLen  = 1 * 1024 * 1024
	LenSecretKey = 32

	//startHeartbeat
	pingPeriod = 2 * time.Second
	pongWait   = 60 * time.Second
	writeWait  = 10 * time.Second

	//autoEndpoint
	pingInterval         = 30 * time.Second
	reconnectMaxAttempts = 5
	reconnectBackoffBase = 1 * time.Second
)

func randLetters(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		// беремо випадковий індекс у діапазоні [0, len(letters))
		idx, _ := crand.Int(crand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[idx.Int64()]
	}
	return string(b)
}
