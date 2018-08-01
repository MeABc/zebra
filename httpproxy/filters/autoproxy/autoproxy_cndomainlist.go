package autoproxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/MeABc/glog"
	"github.com/cloudflare/golibs/lrucache"
	"golang.org/x/sync/singleflight"

	"../../filters"
	"../../helpers"
	"../../proxy"
	"../../storage"
)

var (
	cndomainlistOnceUpdater sync.Once
)

func (f *Filter) CNDomainListInit(config *Config) {
	if f.CNDomainListEnabled {
		var err error

		d0 := &net.Dialer{
			KeepAlive: 30 * time.Second,
			Timeout:   8 * time.Second,
			// DualStack: true,
		}

		d := &helpers.Dialer{
			Dialer: d0,
			Resolver: &helpers.Resolver{
				Singleflight: &singleflight.Group{},
				LRUCache:     lrucache.NewLRUCache(32),
				Hosts:        lrucache.NewLRUCache(4096),
			},
		}

		if config.CNDomainList.EnableRemoteDNS {
			d.Resolver.DNSServer = config.CNDomainList.DNSServer
			_, _, _, err := helpers.ParseIPPort(config.CNDomainList.DNSServer)
			if err != nil {
				glog.Fatalf("AUTOPROXY: helpers.ParseIPPort(%v) failed", config.CNDomainList.DNSServer)
			}
		}

		for host, ip := range config.Hosts {
			if host != "" && ip != "" {
				d.Resolver.Hosts.Set(host, ip, time.Time{})
			}
		}

		d.Resolver.DNSExpiry = time.Duration(config.CNDomainList.Duration) * time.Second
		f.CNDomainListResolver = d.Resolver
		f.CNDomainListResolver.LRUCache = lrucache.NewLRUCache(32)

		f.CNDomainList.Transport = &http.Transport{
			Dial: d.Dial,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				ClientSessionCache: tls.NewLRUClientSessionCache(1000),
			},
			TLSHandshakeTimeout: 8 * time.Second,
		}

		if config.CNDomainList.Proxy.Enabled {
			fixedURL2, err := url.Parse(config.CNDomainList.Proxy.URL)
			if err != nil {
				glog.Fatalf("url.Parse(%#v) error: %s", config.CNDomainList.Proxy.URL, err)
			}

			dialer2, err := proxy.FromURL(fixedURL2, d, nil)
			if err != nil {
				glog.Fatalf("proxy.FromURL(%#v) error: %s", fixedURL2.String(), err)
			}

			f.CNDomainList.Transport.Dial = dialer2.Dial
			f.CNDomainList.Transport.DialTLS = nil
			f.CNDomainList.Transport.Proxy = nil
		}

		f.CNDomainListDomains = NewCNDomainListDomains()
		f.CNDomainListDomains.mu.Lock()
		f.CNDomainListDomains.Domains, err = f.legallyParseDomainList(f.CNDomainList.Filename)
		if err != nil {
			glog.Fatalf("AUTOPROXY: legallyParseDomainList error: %v", err)
		}
		f.CNDomainListDomains.mu.Unlock()

		name := config.CNDomainList.Rule
		if name == "" {
			name = "direct"
		}
		f0, err := filters.GetFilter(name)
		if err != nil {
			glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) for CNDomainList.Rule error: %v", name, err)
		}
		f1, ok := f0.(filters.RoundTripFilter)
		if !ok {
			glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) return %T, not a RoundTripFilter", name, f0)
		}
		f.CNDomainListRule = f1
		f.CNDomainListCache = lrucache.NewLRUCache(8192)

		go cndomainlistOnceUpdater.Do(f.cndomainlistUpdater)
	}
}

func NewCNDomainListDomains() *CNDomainListDomains {
	c := &CNDomainListDomains{
		Domains: nil,
	}
	return c
}

func domainMatchList(d string, cd *CNDomainListDomains) bool {
	if d == "" {
		return false
	}

	cd.mu.RLock()
	defer cd.mu.RUnlock()

	for _, domain := range cd.Domains {
		if d == domain || strings.HasSuffix(d, "."+domain) {
			return true
		}
	}
	return false
}

func (f *Filter) legallyParseDomainList(filename string) ([]string, error) {
	var domains []string
	var domain string

	resp, err := f.Store.Get(filename)
	if err != nil {
		helpers.CloseResponseBody(resp)
		return nil, fmt.Errorf("f.Store.Get(%v) error: %v", filename, err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll(%#v) error: %v", resp.Body, err)
	}

	for _, v := range bytes.Split(data, helpers.StrToBytes("\n")) {
		domain = helpers.BytesToStr(v)
		if domain == "" {
			continue
		}
		domains = append(domains, domain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("empty domain list")
	}

	return domains, nil
}

func (f *Filter) cndomainlistUpdater() {
	// glog.V(2).Infof("start updater for %+v, expiry=%s, duration=%s", f.CNDomainList.URL.String(), f.CNDomainList.Expiry, f.CNDomainList.Duration)

	ticker := time.Tick(f.CNDomainList.Duration)

	for {
		select {
		case <-ticker:
			glog.V(2).Infof("Begin auto china_ip_list(%#v) update...", f.CNDomainList.URL.String())
			resp, err := f.Store.Head(f.CNDomainList.Filename)
			if err != nil {
				glog.Warningf("stat cndomainlist(%#v) err: %v", f.CNDomainList.Filename, err)
				continue
			}

			lm := resp.Header.Get("Last-Modified")
			if lm == "" {
				glog.Warningf("cndomainlist(%#v) header(%#v) does not contains last-modified", f.CNDomainList.Filename, resp.Header)
				continue
			}

			modTime, err := time.Parse(storage.DateFormat, lm)
			if err != nil {
				glog.Warningf("stat cndomainlist(%#v) has parse %#v error: %v", f.CNDomainList.Filename, lm, err)
				continue
			}

			if time.Now().Sub(modTime) < f.CNDomainList.Expiry {
				glog.V(2).Infof("cndomainlist has not updated. update expiry: %v", f.CNDomainList.Expiry)
				continue
			}
		}

		glog.Infof("Downloading %#v", f.CNDomainList.URL.String())

		req, err := http.NewRequest(http.MethodGet, f.CNDomainList.URL.String(), nil)
		if err != nil {
			glog.Warningf("NewRequest(%#v) error: %v", f.CNDomainList.URL.String(), err)
			continue
		}

		resp, err := f.CNDomainList.Transport.RoundTrip(req)
		if err != nil {
			glog.Warningf("%T.RoundTrip(%#v) error: %v", f.CNDomainList.Transport, f.CNDomainList.URL.String(), err.Error())
			helpers.CloseResponseBody(resp)
			continue
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			glog.Warningf("ioutil.ReadAll(%T) error: %v", resp.Body, err)
			helpers.CloseResponseBody(resp)
			continue
		}
		resp.Body.Close()

		_, err = f.Store.Delete(f.CNDomainList.Filename)
		if err != nil {
			glog.Warningf("%T.DeleteObject(%#v) error: %v", f.Store, f.CNDomainList.Filename, err)
			continue
		}

		re := regexp.MustCompile(`server=/(.+)/.+`)
		subMatch := re.FindAllSubmatch(data, -1)

		domainList := make([][]byte, 0, len(subMatch))
		for _, s := range subMatch {
			domainList = append(domainList, s[1])
		}
		if len(domainList) == 0 {
			glog.Warningf("Generate china domains (%#v) failed: got nothing", f.CNDomainList.URL.String())
			continue
		}
		data = bytes.Join(domainList, []byte{0x0A})

		_, err = f.Store.Put(f.CNDomainList.Filename, http.Header{}, ioutil.NopCloser(bytes.NewReader(data)))
		if err != nil {
			glog.Warningf("%T.PutObject(%#v) error: %v", f.Store, f.CNDomainList.Filename, err)
			continue
		}

		f.CNDomainListDomains.mu.Lock()
		f.CNDomainListDomains.Domains, err = f.legallyParseDomainList(f.CNDomainList.Filename)
		if err != nil {
			glog.Fatalf("AUTOPROXY: legallyParseDomainList error: %v", err)
		}
		f.CNDomainListDomains.mu.Unlock()

		f.CNDomainListCache.Clear()

		glog.Infof("Update %#v from %#v OK", f.CNDomainList.Filename, f.CNDomainList.URL.String())
	}
}
