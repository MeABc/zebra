package helpers

import (
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/MeABc/glog"
	"github.com/MeABc/net/http2"
	"github.com/MeABc/quic-go/h2quic"
)

var (
	ReqWriteExcludeHeader = map[string]bool{
		"Vary":                true,
		"Via":                 true,
		"X-Forwarded-For":     true,
		"Proxy-Authorization": true,
		"Proxy-Connection":    true,
		"Upgrade":             true,
		"X-Chrome-Variations": true,
		"Connection":          true,
		"Cache-Control":       true,
	}
)

func CloseConnections(tr http.RoundTripper) {
	f := func(_ net.Addr) bool { return true }

	switch tr.(type) {
	case *http.Transport:
		tr.(*http.Transport).CloseConnection(f)
	case *http2.Transport:
		tr.(*http2.Transport).CloseConnection(f)
	case *h2quic.RoundTripper:
		tr.(*h2quic.RoundTripper).CloseConnection(f)
	default:
		glog.Errorf("%T(%v) has not implement CloseConnection method", tr, tr)
	}
}

func CloseConnectionByRemoteHost(tr http.RoundTripper, host string) {
	if host1, _, err := net.SplitHostPort(host); err == nil {
		host = host1
	}

	f := func(raddr net.Addr) bool {
		if host1, _, err := net.SplitHostPort(raddr.String()); err == nil {
			return host == host1
		}
		return false
	}

	switch tr.(type) {
	case *http.Transport:
		tr.(*http.Transport).CloseConnection(f)
	case *http2.Transport:
		tr.(*http2.Transport).CloseConnection(f)
	case *h2quic.RoundTripper:
		tr.(*h2quic.RoundTripper).CloseConnection(f)
	default:
		glog.Errorf("%T(%v) has not implement CloseConnection method", tr, tr)
	}
}

func FixRequestURL(req *http.Request) {
	if req.URL.Host == "" {
		switch {
		case req.Host != "":
			req.URL.Host = req.Host
		case req.TLS != nil:
			req.URL.Host = req.TLS.ServerName
		}
	}
}

func FixRequestHeader(req *http.Request) {
	if req.ContentLength > 0 {
		if req.Header.Get("Content-Length") == "" {
			req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
		}
	}
}

// CloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func CloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}

func GetHostName(req *http.Request) string {
	if host, _, err := net.SplitHostPort(req.Host); err == nil {
		return host
	} else {
		return req.Host
	}
}

func IsStaticRequest(req *http.Request) bool {
	switch path.Ext(req.URL.Path) {
	case "bmp", "gif", "ico", "jpeg", "jpg", "png", "tif", "tiff", "dmg",
		"3gp", "3gpp", "avi", "f4v", "flv", "m4p", "mkv", "mp4", "mp3", "m4v",
		"woff2", "woff", "webm", "ogg", "exe", "zip", "bz2", "rar", "7z",
		"mp4v", "mpv4", "rmvb", "webp", ".js", ".iso", ".xz", ".css", "json":
		return true
	case "":
		name := path.Base(req.URL.Path)
		if strings.Contains(name, "play") ||
			strings.Contains(name, "video") {
			return true
		}
	default:
		if req.Header.Get("Range") != "" ||
			strings.Contains(req.Host, "img.") ||
			strings.Contains(req.Host, "cache.") ||
			strings.Contains(req.Host, "video.") ||
			strings.Contains(req.Host, "static.") ||
			strings.HasPrefix(req.Host, "img") ||
			strings.HasPrefix(req.URL.Path, "/static") ||
			strings.HasPrefix(req.URL.Path, "/asset") ||
			strings.Contains(req.URL.Path, "static") ||
			strings.Contains(req.URL.Path, "asset") ||
			strings.Contains(req.URL.Path, "/cache/") {
			return true
		}
	}
	return false
}

func CloseResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}
}

func CloseWithBlackStatusBadRequest(
	rt http.RoundTripper,
	md *MultiDialer,
	req *http.Request,
	resp *http.Response,
	err error,
) {
	if addr, err := ReflectRemoteAddrFromResponse(resp); err == nil {
		if ip, _, err := net.SplitHostPort(addr); err == nil {
			if md != nil {
				duration := 5 * time.Minute
				glog.Warningf("GAE: %s req.Method: %s, HTTP StatusCode: %d, add to blacklist for %v", ip, req.Method, resp.StatusCode, duration)
				md.IPBlackList.Set(ip, struct{}{}, time.Now().Add(duration))
				CloseConnectionByRemoteHost(rt, ip)
			}
		}
	}
}

func CloseWithBlackContextCanceled(
	rt http.RoundTripper,
	md *MultiDialer,
	err error,
) {
	if ne, ok := err.(*net.OpError); ok && ne != nil && ne.Addr != nil {
		if ne.Op == "read" && ne.Err.Error() == "context canceled" || ne.Err.Error() == "context deadline exceeded" {
			if ip, _, err := net.SplitHostPort(ne.Addr.String()); err == nil {
				CloseConnectionByRemoteHost(rt, ip)
				if md != nil {
					duration := 5 * time.Minute
					glog.Warningf("GAE: %s is context.Canceled, add to blacklist for %v", ip, duration)
					md.IPBlackList.Set(ip, struct{}{}, time.Now().Add(duration))
				}
			}
		}
	}
}

func CloseWithBlackQUICPeerGoingAway(
	rt http.RoundTripper,
	md *MultiDialer,
	err error,
) {
	if ne, ok := err.(*net.OpError); ok && ne != nil && ne.Addr != nil {
		if ne.Op == "read" && ne.Err.Error() == "InvalidHeadersStreamData: PeerGoingAway: " {
			if ip, _, err := net.SplitHostPort(ne.Addr.String()); err == nil {
				CloseConnectionByRemoteHost(rt, ip)
				if md != nil {
					duration := 5 * time.Minute
					glog.Warningf("GAE: %s is PeerGoingAway, add to blacklist for %v", ip, duration)
					md.IPBlackList.Set(ip, struct{}{}, time.Now().Add(duration))
				}
			}
		}
	}
}
