package direct

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/MeABc/glog"
	"github.com/MeABc/net/http2"
	"github.com/cloudflare/golibs/lrucache"
	"golang.org/x/sync/singleflight"

	"../../filters"
	"../../helpers"
	"../../proxy"
	"../../storage"
)

const (
	filterName string = "direct"
)

type Config struct {
	Transport struct {
		Dialer struct {
			Timeout        int
			KeepAlive      int
			DualStack      bool
			DNSCacheExpiry int
			DNSCacheSize   uint
		}
		Proxy struct {
			Enabled bool
			URL     string
		}
		TLSClientConfig struct {
			MinVersion             string
			InsecureSkipVerify     bool
			ClientSessionCacheSize int
		}
		EnableRemoteDNS     bool
		DNSServer           string
		DNSBlackLocalIP     bool
		DisableKeepAlives   bool
		DisableCompression  bool
		TLSHandshakeTimeout int
		MaxIdleConnsPerHost int
		Hosts               map[string]string
	}
}

type Filter struct {
	Config
	filters.RoundTripFilter
	transport *http.Transport
}

func init() {
	filters.Register(filterName, func() (filters.Filter, error) {
		filename := filterName + ".json"
		config := new(Config)
		err := storage.LookupStoreByFilterName(filterName).UnmarshallJson(filename, config)
		if err != nil {
			glog.Fatalf("storage.ReadJsonConfig(%#v) failed: %s", filename, err)
		}
		return NewFilter(config)
	})
}

func NewFilter(config *Config) (filters.Filter, error) {
	d := &helpers.Dialer{
		Dialer: &net.Dialer{
			KeepAlive: time.Duration(config.Transport.Dialer.KeepAlive) * time.Second,
			Timeout:   time.Duration(config.Transport.Dialer.Timeout) * time.Second,
			DualStack: config.Transport.Dialer.DualStack,
		},
		Resolver: &helpers.Resolver{
			Singleflight: &singleflight.Group{},
			LRUCache:     lrucache.NewLRUCache(config.Transport.Dialer.DNSCacheSize),
			Hosts:        lrucache.NewLRUCache(8192),
			DNSExpiry:    time.Duration(config.Transport.Dialer.DNSCacheExpiry) * time.Second,
		},
	}
	if config.Transport.EnableRemoteDNS {
		d.Resolver.DNSServer = config.Transport.DNSServer
		_, _, _, err := helpers.ParseIPPort(config.Transport.DNSServer)
		if err != nil {
			glog.Fatalf("DIRECT: helpers.ParseIPPort(%v) failed", config.Transport.DNSServer)
		}
	}

	if config.Transport.DNSBlackLocalIP {
		d.Resolver.BlackList = lrucache.NewLRUCache(1024)
		if ips, err := helpers.LocalIPv4s(); err == nil {
			for _, ip := range ips {
				d.Resolver.BlackList.Set(ip.String(), struct{}{}, time.Time{})
			}
			for _, s := range []string{"127.0.0.1", "::1"} {
				d.Resolver.BlackList.Set(s, struct{}{}, time.Time{})
			}
		}
	}

	for host, ip := range config.Transport.Hosts {
		if host != "" && ip != "" {
			d.Resolver.Hosts.Set(host, ip, time.Time{})
		}
	}

	tr := &http.Transport{
		Dial: d.Dial,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: config.Transport.TLSClientConfig.InsecureSkipVerify,
			ClientSessionCache: tls.NewLRUClientSessionCache(config.Transport.TLSClientConfig.ClientSessionCacheSize),
		},
		TLSHandshakeTimeout: time.Duration(config.Transport.TLSHandshakeTimeout) * time.Second,
		MaxIdleConnsPerHost: config.Transport.MaxIdleConnsPerHost,
		DisableCompression:  config.Transport.DisableCompression,
	}
	if v := helpers.TLSVersion(config.Transport.TLSClientConfig.MinVersion); v != 0 {
		tr.TLSClientConfig.MinVersion = v
	} else {
		tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	}

	if config.Transport.Proxy.Enabled {
		fixedURL, err := url.Parse(config.Transport.Proxy.URL)
		if err != nil {
			glog.Fatalf("url.Parse(%#v) error: %s", config.Transport.Proxy.URL, err)
		}

		dialer, err := proxy.FromURL(fixedURL, d, nil)
		if err != nil {
			glog.Fatalf("proxy.FromURL(%#v) error: %s", fixedURL.String(), err)
		}

		tr.Dial = dialer.Dial
		tr.DialTLS = nil
		tr.Proxy = nil
	}

	if tr.TLSClientConfig != nil {
		err := http2.ConfigureTransport(tr)
		if err != nil {
			glog.Warningf("DIRECT: Error enabling Transport HTTP/2 support: %v", err)
		}
	}

	return &Filter{
		Config:    *config,
		transport: tr,
	}, nil
}

func (f *Filter) FilterName() string {
	return filterName
}

func (f *Filter) RoundTrip(ctx context.Context, req *http.Request) (context.Context, *http.Response, error) {
	switch req.Method {
	case "CONNECT":
		glog.V(2).Infof("%s \"DIRECT %s %s %s\" - -", req.RemoteAddr, req.Method, req.Host, req.Proto)
		rconn, err := f.transport.Dial("tcp", req.Host)
		if err != nil {
			return ctx, nil, err
		}

		rw := filters.GetResponseWriter(ctx)

		hijacker, ok := rw.(http.Hijacker)
		if !ok {
			return ctx, nil, fmt.Errorf("http.ResponseWriter(%#v) does not implments http.Hijacker", rw)
		}

		flusher, ok := rw.(http.Flusher)
		if !ok {
			return ctx, nil, fmt.Errorf("http.ResponseWriter(%#v) does not implments http.Flusher", rw)
		}

		rw.WriteHeader(http.StatusOK)
		flusher.Flush()

		lconn, _, err := hijacker.Hijack()
		if err != nil {
			return ctx, nil, fmt.Errorf("%#v.Hijack() error: %v", hijacker, err)
		}
		defer lconn.Close()

		go helpers.IOCopy(rconn, lconn)
		helpers.IOCopy(lconn, rconn)

		return ctx, filters.DummyResponse, nil
	default:
		helpers.FixRequestURL(req)
		helpers.FixRequestHeader(req)
		resp, err := f.transport.RoundTrip(req)

		if err != nil {
			helpers.CloseResponseBody(resp)
			return ctx, nil, err
		}

		if req.RemoteAddr != "" {
			glog.V(2).Infof("%s \"DIRECT %s %s %s\" %d %s", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, resp.StatusCode, resp.Header.Get("Content-Length"))
		}

		return ctx, resp, err
	}
}
