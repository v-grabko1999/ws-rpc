package wetsock

import "time"

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
)
