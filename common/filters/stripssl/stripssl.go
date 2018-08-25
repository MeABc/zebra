package stripssl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MeABc/glog"
	"github.com/cloudflare/golibs/lrucache"

	"../../filters"
	"../../helpers"
	"../../storage"
)

const (
	filterName string = "stripssl"
)

type Config struct {
	TLSVersion string
	RootCA     struct {
		Filename string
		Dirname  string
		Name     string
		Duration int
		Portable bool
	}
	Ports              []int
	Ignores            []string
	DirectSkipStripSSL bool
	Sites              []string
}

type Filter struct {
	Config
	CA                 *RootCA
	CAExpiry           time.Duration
	TLSMaxVersion      uint16
	TLSConfigCache     lrucache.Cache
	Ports              map[string]struct{}
	Ignores            map[string]struct{}
	DirectSkipStripSSL bool
	Sites              *helpers.HostMatcher
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

var (
	defaultCA *RootCA
	onceCA    sync.Once
)

func NewFilter(config *Config) (_ filters.Filter, err error) {
	onceCA.Do(func() {
		defaultCA, err = NewRootCA(config.RootCA.Name,
			time.Duration(config.RootCA.Duration)*time.Second,
			config.RootCA.Dirname,
			config.RootCA.Portable)
		if err != nil {
			glog.Fatalf("NewRootCA(%#v) error: %v", config.RootCA.Name, err)
		}
	})

	f := &Filter{
		Config:             *config,
		TLSMaxVersion:      tls.VersionTLS12,
		CA:                 defaultCA,
		CAExpiry:           time.Duration(config.RootCA.Duration) * time.Second,
		TLSConfigCache:     lrucache.NewMultiLRUCache(4, 4096),
		Ports:              make(map[string]struct{}),
		Ignores:            make(map[string]struct{}),
		DirectSkipStripSSL: config.DirectSkipStripSSL,
		Sites:              helpers.NewHostMatcher(config.Sites),
	}

	if v := helpers.TLSVersion(config.TLSVersion); v != 0 {
		f.TLSMaxVersion = v
	}

	for _, port := range config.Ports {
		f.Ports[strconv.Itoa(port)] = struct{}{}
	}

	for _, ignore := range config.Ignores {
		f.Ignores[ignore] = struct{}{}
	}

	return f, nil
}

func (f *Filter) FilterName() string {
	return filterName
}

func (f *Filter) Request(ctx context.Context, req *http.Request) (context.Context, *http.Request, error) {
	if req.Method != http.MethodConnect {
		return ctx, req, nil
	}

	if f1 := filters.GetRoundTripFilter(ctx); f1 != nil {
		if _, ok := f.Ignores[f1.FilterName()]; ok {
			return ctx, req, nil
		}
		f.DirectSkipStripSSL = false
	}

	if f.DirectSkipStripSSL {
		return ctx, req, nil
	}

	host, port, err := net.SplitHostPort(req.RequestURI)
	if err != nil {
		return ctx, req, nil
	}

	if !f.Sites.Match(host) {
		return ctx, req, nil
	}

	needStripSSL := true
	if _, ok := f.Ports[port]; !ok {
		needStripSSL = false
	}

	rw := filters.GetResponseWriter(ctx)
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		return ctx, nil, fmt.Errorf("%#v does not implments Hijacker", rw)
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		return ctx, nil, fmt.Errorf("http.ResponseWriter Hijack failed: %s", err)
	}

	_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
	if err != nil {
		conn.Close()
		return ctx, nil, err
	}

	glog.V(2).Infof("%s \"STRIP %s %s %s\" - -", req.RemoteAddr, req.Method, req.Host, req.Proto)

	var c net.Conn = conn
	if needStripSSL {
		GetConfigForClient := func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			host := req.Host
			ua := req.UserAgent()

			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}

			name := helpers.GetCommonName(host)
			ecc := helpers.SupportsECDSA(hello)

			var md5hash string
			var cacheKey strings.Builder
			cacheKey.WriteString(name)
			cacheKey.WriteString(ua)
			if ecc {
				cacheKey.WriteString("ecc")
			} else {
				cacheKey.WriteString("rsa")
			}
			md5hash = helpers.GetMD5Hash(cacheKey.String())
			cacheKey.Reset()

			var config interface{}
			var ok bool
			if config, ok = f.TLSConfigCache.Get(md5hash); !ok {
				cert, err := f.CA.Issue(name, f.CAExpiry, ecc)
				if err != nil {
					return nil, err
				}
				pool := x509.NewCertPool()
				pool.AddCert(f.CA.ca)
				config = &tls.Config{
					CipherSuites:             hello.CipherSuites,
					Certificates:             []tls.Certificate{*cert},
					RootCAs:                  pool,
					MaxVersion:               helpers.TLSMaxVersion(hello.SupportedVersions),
					MinVersion:               tls.VersionTLS10,
					PreferServerCipherSuites: true,
					Renegotiation:            tls.RenegotiateFreelyAsClient,
				}

				if hello.SupportedCurves != nil {
					config.(*tls.Config).CurvePreferences = hello.SupportedCurves
				}

				f.TLSConfigCache.Set(md5hash, config, time.Now().Add(24*time.Hour))
			}
			return config.(*tls.Config), nil
		}

		pool := x509.NewCertPool()
		pool.AddCert(f.CA.ca)

		cert := tls.Certificate{
			Certificate: [][]byte{f.CA.derBytes},
			PrivateKey:  f.CA.priv,
		}

		config := &tls.Config{
			GetConfigForClient:          GetConfigForClient,
			ClientAuth:                  tls.RequireAndVerifyClientCert,
			Certificates:                []tls.Certificate{cert},
			ClientCAs:                   pool,
			MaxVersion:                  f.TLSMaxVersion,
			MinVersion:                  tls.VersionTLS10,
			SessionTicketsDisabled:      false,
			DynamicRecordSizingDisabled: false,
			ClientSessionCache:          tls.NewLRUClientSessionCache(1024),
			PreferServerCipherSuites:    true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA256,
			},
			Renegotiation: tls.RenegotiateFreelyAsClient,
		}

		tlsConn := tls.Server(conn, config)

		if err := tlsConn.Handshake(); err != nil {
			glog.V(2).Infof("%s %T.Handshake() error: %#v", req.RemoteAddr, tlsConn, err)
			conn.Close()
			return ctx, nil, err
		}

		c = tlsConn
	}

	if ln1, ok := filters.GetListener(ctx).(helpers.Listener); ok {
		ln1.Add(c)
		return ctx, filters.DummyRequest, nil
	}

	loConn, err := net.Dial("tcp", filters.GetListener(ctx).Addr().String())
	if err != nil {
		return ctx, nil, err
	}

	go helpers.IOCopy(loConn, c)
	go helpers.IOCopy(c, loConn)

	return ctx, filters.DummyRequest, nil
}
