package helpers

import (
	"io"
	"sync"
	// "github.com/cloudflare/golibs/bytepool"
)

const (
	BUFSZ = 32 * 1024
)

var (
	bufpool = sync.Pool{
		New: func() interface{} {
			return make([]byte, BUFSZ)
		},
	}
)

func IOCopy(dst io.Writer, src io.Reader) (written int64, err error) {
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}

	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}

	buf := bufpool.Get().([]byte)
	written, err = io.CopyBuffer(dst, src, buf)
	bufpool.Put(buf)

	return written, err
}
