package wetsock

import (
	"log"
	"sync"

	"github.com/klauspost/compress/zstd"

)

var zstdDecoderPool = sync.Pool{
	New: func() any {
		dec, err := zstd.NewReader(nil)
		if err != nil {
			log.Panicf("wetsock: не вдалося створити zstd.Decoder: %v", err)
		}
		return dec
	},
}

var zstdEncoderPool = sync.Pool{
	New: func() any {
		// Максимальний рівень стиснення
		enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		if err != nil {
			log.Panicf("wetsock: не вдалося створити zstd.Encoder: %v", err)
		}
		return enc
	},
}
