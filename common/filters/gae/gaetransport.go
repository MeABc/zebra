package gae

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MeABc/glog"
	quic "github.com/MeABc/quic-go"
	"github.com/MeABc/quic-go/h2quic"

	"../../helpers"
)

type Transport struct {
	RoundTripper http.RoundTripper
	MultiDialer  *helpers.MultiDialer
	RetryTimes   int
}

// https://github.com/golang/lint/blob/master/testdata/contextkeytypes.go
type responseHeaderTimeoutKey struct{}

const (
	DefaultResponseContextTimeout time.Duration = 8 * time.Second
)

type QuicBody struct {
	quic.Stream
	Transport   *h2quic.RoundTripper
	MultiDialer *helpers.MultiDialer
}

func (b *QuicBody) OnError(err error) {
	var shouldClose bool

	if te, ok := err.(interface {
		Timeout() bool
	}); ok && te.Timeout() {
		shouldClose = true
	}

	if shouldClose {
		b.Transport.Close()
		ip, _, _ := net.SplitHostPort(b.RemoteAddr().String())
		duration := 5 * time.Minute
		glog.Warningf("GAE: QuicBody(%v) is timeout, add to blacklist for %v", ip, duration)
		b.MultiDialer.IPBlackList.Set(ip, struct{}{}, time.Now().Add(duration))
	}

	if e, ok := err.(interface {
		Error() string
	}); ok && e.Error() == "PeerGoingAway: " {
		b.Transport.Close()
	}
}

func (t *Transport) roundTripQuic(req *http.Request) (*http.Response, error) {
	t1 := t.RoundTripper.(*h2quic.RoundTripper)

	if !strings.HasSuffix(req.Host, ".appspot.com") {
		req = req.WithContext(context.WithValue(req.Context(), responseHeaderTimeoutKey{}, DefaultResponseContextTimeout))
	}

	resp, err := t1.RoundTrip(req)

	if ne, ok := err.(*net.OpError); ok && ne != nil {
		if ne.Error() == "PeerGoingAway: " || ne.Error() == "context deadline exceeded" || ne.Error() == "context canceled" {
			t1.Close()
		}
	}

	if resp != nil && resp.Body != nil {
		if stream, ok := resp.Body.(quic.Stream); ok {
			resp.Body = &QuicBody{
				Stream:      stream,
				Transport:   t1,
				MultiDialer: t.MultiDialer,
			}
		}
	}

	return resp, err
}

func (t *Transport) roundTripTLS(req *http.Request) (*http.Response, error) {
	req = req.WithContext(context.WithValue(req.Context(), responseHeaderTimeoutKey{}, DefaultResponseContextTimeout))

	resp, err := t.RoundTripper.RoundTrip(req)

	if ne, ok := err.(*net.OpError); ok && ne != nil && ne.Addr != nil {
		if ne.Error() == "unexpected EOF" {
			helpers.CloseConnections(t.RoundTripper)
		}
		if ne.Timeout() || ne.Op == "read" {
			ip, _, _ := net.SplitHostPort(ne.Addr.String())
			glog.Warningf("GAE %s RoundTrip %s error: %#v, close connection to it", ne.Net, ip, ne.Err)
			helpers.CloseConnectionByRemoteHost(t.RoundTripper, ip)
			if t.MultiDialer != nil {
				duration := 5 * time.Minute
				glog.Warningf("GAE: %s is timeout, add to blacklist for %v", ip, duration)
				t.MultiDialer.IPBlackList.Set(ip, struct{}{}, time.Now().Add(duration))
			}
		}
	}

	return resp, err
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var err error
	var resp *http.Response

	_, isQuic := t.RoundTripper.(*h2quic.RoundTripper)

	retry := t.RetryTimes
	if req.Method != http.MethodGet && req.Header.Get("Content-Length") != "" {
		retry = 1
	}

	for i := 0; i < retry; i++ {
		if isQuic {
			resp, err = t.roundTripQuic(req)
		} else {
			resp, err = t.roundTripTLS(req)
		}

		if err != nil {
			glog.Warningf("GAE %T.RoundTrip(%#v) error: %+v", t.RoundTripper, req.URL.String(), err)

			helpers.CloseResponseBody(resp)
			if isQuic {
				helpers.CloseWithBlackQUICPeerGoingAway(t.RoundTripper, t.MultiDialer, err)
			}
			helpers.CloseWithBlackContextCanceled(t.RoundTripper, t.MultiDialer, err)
			continue
		}

		if resp != nil && resp.StatusCode == http.StatusBadRequest {
			glog.Warningf("GAE %T.RoundTrip(%#v) %s HTTP Error %d", t.RoundTripper, req.URL.String(), req.Method, resp.StatusCode)

			helpers.CloseWithBlackStatusBadRequest(t.RoundTripper, t.MultiDialer, req, resp, err)
			if i == retry-1 {
				return resp, err
			}
			helpers.CloseResponseBody(resp)
			continue
		}

		break
	}

	if resp != nil && resp.StatusCode >= http.StatusBadRequest {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			helpers.CloseResponseBody(resp)
			return nil, err
		}

		if addr, err := helpers.ReflectRemoteAddrFromResponse(resp); err == nil {
			if ip, _, err := net.SplitHostPort(addr); err == nil {
				var duration time.Duration

				if resp.StatusCode == http.StatusBadGateway && (bytes.Contains(body, helpers.StrToBytes("Please try again in 30 seconds.")) || bytes.Contains(body, helpers.StrToBytes("This page cannot be loaded using Chrome Data Saver. Try reloading the page."))) {
					duration = 1 * time.Hour
				} else if resp.StatusCode >= 301 && resp.Header.Get("Location") != "" {
					duration = 2 * time.Hour
				} else if resp.StatusCode == http.StatusNotFound && bytes.Contains(body, helpers.StrToBytes("<ins>That’s all we know.</ins>")) {
					server := resp.Header.Get("Server")
					if server != "gws" && !strings.HasPrefix(server, "gvs") {
						if t.MultiDialer.TLSConnDuration.Len() > 10 {
							duration = 5 * time.Minute
						}
					}
				}

				if duration > 0 && t.MultiDialer != nil {
					glog.Warningf("GAE: %s StatusCode is %d, not a gws/gvs ip, add to blacklist for %v", ip, resp.StatusCode, duration)
					t.MultiDialer.IPBlackList.Set(ip, struct{}{}, time.Now().Add(duration))
					helpers.CloseConnectionByRemoteHost(t.RoundTripper, ip)
				}
			}
		}

		resp.Body.Close()
		resp.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	return resp, err
}

type GAETransport struct {
	Transport   *Transport
	MultiDialer *helpers.MultiDialer
	Servers     *Servers
	BrotliSites *helpers.HostMatcher
	Deadline    time.Duration
	RetryDelay  time.Duration
	RetryTimes  int
}

func (t *GAETransport) RoundTrip(req *http.Request) (*http.Response, error) {
	deadline := t.Deadline
	brotli := t.BrotliSites.Match(req.Host) && strings.Contains(req.Header.Get("Accept-Encoding"), "br")
	retryTimes := t.RetryTimes
	retryDelay := t.RetryDelay
	for i := 0; i < retryTimes; i++ {
		server := t.Servers.PickFetchServer(req, i)
		req1, err := t.Servers.EncodeRequest(req, server, deadline, brotli)
		if err != nil {
			return nil, fmt.Errorf("GAE EncodeRequest: %s", err.Error())
		}

		resp, err := t.Transport.RoundTrip(req1)

		if err != nil {
			helpers.CloseResponseBody(resp)
			if i == retryTimes-1 {
				return nil, err
			}
			glog.Warningf("GAE: request \"%s\" error: %T(%v), retry...", req.URL.String(), err, err)

			helpers.CloseWithBlackContextCanceled(t.Transport.RoundTripper, t.MultiDialer, err)

			continue
		}

		if resp.StatusCode != http.StatusOK {
			if i == retryTimes-1 {
				return resp, nil
			}

			switch resp.StatusCode {
			case http.StatusServiceUnavailable:
				glog.Warningf("GAE: %s over qouta, try switch to next appid...", server.Host)
				t.Servers.ToggleBadServer(server)
				time.Sleep(retryDelay)
				helpers.CloseResponseBody(resp)
				continue
			case http.StatusFound,
				http.StatusBadGateway,
				http.StatusNotFound,
				http.StatusMethodNotAllowed:
				if t.MultiDialer != nil {
					if addr, err := helpers.ReflectRemoteAddrFromResponse(resp); err == nil {
						if ip, _, err := net.SplitHostPort(addr); err == nil {
							duration := 8 * time.Hour
							glog.Warningf("GAE: %s StatusCode is %d, not a gws/gvs ip, add to blacklist for %v", ip, resp.StatusCode, duration)
							t.MultiDialer.IPBlackList.Set(ip, struct{}{}, time.Now().Add(duration))
							helpers.CloseConnectionByRemoteHost(t.Transport.RoundTripper, ip)
						}
					}
				}
				helpers.CloseResponseBody(resp)
				continue
			case http.StatusBadRequest:
				helpers.CloseWithBlackStatusBadRequest(t.Transport.RoundTripper, t.MultiDialer, req, resp, err)
				helpers.CloseResponseBody(resp)
				continue
			default:
				return resp, nil
			}
		}

		resp1, err := t.Servers.DecodeResponse(resp)
		if err != nil {
			helpers.CloseResponseBody(resp)
			helpers.CloseResponseBody(resp1)
			return nil, err
		}
		if resp1 != nil {
			resp1.Request = req
		}
		if i == retryTimes-1 {
			return resp1, err
		}

		switch resp1.StatusCode {
		case http.StatusBadGateway:
			body, err := ioutil.ReadAll(resp1.Body)
			if err != nil {
				helpers.CloseResponseBody(resp1)
				return nil, err
			}
			resp1.Body.Close()

			if bytes.Contains(body, helpers.StrToBytes("DEADLINE_EXCEEDED")) {
				//FIXME: deadline += 10 * time.Second
				glog.Warningf("GAE: %s urlfetch %#v get DEADLINE_EXCEEDED, retry with deadline=%s...", req1.Host, req.URL.String(), deadline)
				time.Sleep(deadline)
				continue
			}
			if bytes.Contains(body, helpers.StrToBytes("ver quota")) {
				glog.Warningf("GAE: %s urlfetch %#v get over quota, retry...", req1.Host, req.URL.String())
				t.Servers.ToggleBadServer(server)
				time.Sleep(retryDelay)
				continue
			}
			if bytes.Contains(body, helpers.StrToBytes("urlfetch: CLOSED")) {
				glog.Warningf("GAE: %s urlfetch %#v get urlfetch: CLOSED, retry...", req1.Host, req.URL.String())
				time.Sleep(retryDelay)
				continue
			}
			resp1.Body = ioutil.NopCloser(bytes.NewReader(body))
			return resp1, nil
		default:
			return resp1, nil
		}
	}

	return nil, fmt.Errorf("GAE: cannot reach here with %#v", req)
}
