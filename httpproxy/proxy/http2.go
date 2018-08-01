// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/MeABc/net/http2"
)

type TLSDialer interface {
	DialTLS(network, addr string, cfg *tls.Config) (net.Conn, error)
}

func HTTP2(network, addr string, auth *Auth, forward Dialer, resolver Resolver) (Dialer, error) {
	var hostname string

	if host, _, err := net.SplitHostPort(addr); err == nil {
		hostname = host
	} else {
		hostname = addr
		addr = net.JoinHostPort(addr, "443")
	}

	h := &h2{
		network:  network,
		addr:     addr,
		hostname: hostname,
		forward:  forward,
	}
	if auth != nil {
		h.user = auth.User
		h.password = auth.Password
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: false,
		ServerName:         h.hostname,
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	}

	h.transport = &http2.Transport{
		DisableCompression: false,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := h.forward.Dial(h.network, h.addr)
			if err != nil {
				return nil, err
			}

			tlsConn := tls.Client(conn, tlsConfig)

			err = tlsConn.Handshake()
			if err != nil {
				return nil, err
			}

			return tlsConn, nil
		},
	}

	if d, ok := h.forward.(TLSDialer); ok {
		h.transport.DialTLS = func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return d.DialTLS(h.network, h.addr, tlsConfig)
		}
	}

	return h, nil
}

type h2 struct {
	user, password string
	network, addr  string
	hostname       string
	forward        Dialer
	transport      *http2.Transport
}

// Dial connects to the address addr on the network net via the HTTP1 proxy.
func (h *h2) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for HTTP proxy connections of type " + network)
	}

	pr, pw := io.Pipe()
	req := &http.Request{
		ProtoMajor: 2,
		Method:     http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   addr,
		},
		Host: addr,
		Header: http.Header{
			"Content-Type": []string{"application/octet-stream"},
			"User-Agent":   []string{"Mozilla/5.0"},
		},
		Body:          pr,
		ContentLength: -1,
	}

	if h.user != "" && h.password != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString(StrToBytes(h.user+":"+h.password)))
	}

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var errmsg string
		if resp.Body != nil {
			data := make([]byte, 1024)
			if n, err := resp.Body.Read(data); err != nil {
				errmsg = err.Error()
			} else {
				errmsg = string(data[:n])
			}
		}
		return nil, errors.New("proxy: read from " + h.addr + " error: " + resp.Status + ": " + errmsg)
	}

	conn := &http2Conn{
		r:      resp.Body,
		w:      pw,
		closed: make(chan struct{}),
	}

	return conn, nil
}

type http2Conn struct {
	r io.ReadCloser
	w io.Writer

	remoteAddr net.Addr
	localAddr  net.Addr

	closed chan struct{}
}

func (c *http2Conn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *http2Conn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *http2Conn) Close() (err error) {
	select {
	case <-c.closed:
		return
	default:
		close(c.closed)
	}
	if rc, ok := c.r.(io.Closer); ok {
		err = rc.Close()
	}
	if w, ok := c.w.(io.Closer); ok {
		err = w.Close()
	}
	return
}

func (c *http2Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http2Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http2Conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}
