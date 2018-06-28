package helpers

import (
	"io"

	"github.com/juju/ratelimit"
)

type multiReadCloser struct {
	readers     []io.Reader
	multiReader io.Reader
}

func NewMultiReadCloser(readers ...io.Reader) io.ReadCloser {
	return &multiReadCloser{
		readers:     readers,
		multiReader: io.MultiReader(readers...),
	}
}

func (r *multiReadCloser) Read(p []byte) (n int, err error) {
	return r.multiReader.Read(p)
}

func (r *multiReadCloser) Close() (err error) {
	for _, r := range r.readers {
		if c, ok := r.(io.Closer); ok {
			if e := c.Close(); e != nil {
				err = e
			}
		}
	}

	return err
}

type xorReadCloser struct {
	rc  io.ReadCloser
	key []byte
}

func NewXorReadCloser(rc io.ReadCloser, key []byte) io.ReadCloser {
	return &xorReadCloser{
		rc:  rc,
		key: key,
	}
}

func (x *xorReadCloser) Read(p []byte) (n int, err error) {
	n, err = x.rc.Read(p)
	c := x.key[0]
	for i := 0; i < n; i++ {
		p[i] ^= c
	}

	return n, err
}

func (x *xorReadCloser) Close() error {
	return x.rc.Close()
}

type rateLimitReader struct {
	rc  io.ReadCloser // underlying reader
	rlr io.Reader     // ratelimit.Reader
}

func NewRateLimitReader(rc io.ReadCloser, rate float64, capacity int64) io.ReadCloser {
	var rlr rateLimitReader

	rlr.rc = rc
	rlr.rlr = ratelimit.Reader(rc, ratelimit.NewBucketWithRate(rate, capacity))

	return &rlr
}

func (rlr *rateLimitReader) Read(p []byte) (n int, err error) {
	return rlr.rlr.Read(p)
}

func (rlr *rateLimitReader) Close() error {
	return rlr.rc.Close()
}

type ReaderCloser struct {
	Reader io.Reader
	Closer io.ReadCloser
}

func (bc ReaderCloser) Read(buf []byte) (int, error) {
	return bc.Reader.Read(buf)
}

func (bc ReaderCloser) Close() error {
	return bc.Closer.Close()
}

// Error http: invalid read on closed body
// https://github.com/wuyongxiu/wuyongxiu.github.io/issues/14
// https://github.com/flynn/flynn/issues/872
// https://github.com/flynn/flynn/pull/875/files
type FakeCloseReadCloser struct {
	io.ReadCloser
}

func (w *FakeCloseReadCloser) Close() error {
	return nil
}

func (w *FakeCloseReadCloser) RealClose() error {
	if w.ReadCloser == nil {
		return nil
	}
	return w.ReadCloser.Close()
}
