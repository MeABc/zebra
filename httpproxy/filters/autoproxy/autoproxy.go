package autoproxy

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MeABc/glog"
	"github.com/cloudflare/golibs/lrucache"
	"github.com/wangtuanjie/ip17mon"

	"../../filters"
	"../../helpers"
	"../../proxy"
	"../../storage"
)

const (
	filterName string = "autoproxy"
)

type Config struct {
	SiteFilters struct {
		Enabled bool
		Rules   map[string]string
	}
	CNIPList struct {
		Enabled         bool
		Rule            string
		URL             string
		File            string
		Expiry          int
		Duration        int
		EnableRemoteDNS bool
		DNSServer       string
		Proxy           struct {
			Enabled bool
			URL     string
		}
	}
	RegionFilters struct {
		Enabled         bool
		DataFile        string
		EnableRemoteDNS bool
		DNSServer       string
		DNSCacheSize    int
		Rules           map[string]string
		IPRules         map[string]string
	}
	IndexFiles struct {
		Enabled    bool
		ServerName string
		Files      []string
	}
	GFWList struct {
		Enabled         bool
		URL             string
		File            string
		Encoding        string
		Expiry          int
		Duration        int
		EnableRemoteDNS bool
		DNSServer       string
		Proxy           struct {
			Enabled bool
			URL     string
		}
	}
	MobileConfig struct {
		Enabled bool
	}
	IPHTML struct {
		Enabled   bool
		WhiteList []string
	}
	BlackList struct {
		Enabled   bool
		SiteRules []string
	}
}

var (
	pacOnceUpdater      sync.Once
	cniplistOnceUpdater sync.Once
)

type GFWList struct {
	URL       *url.URL
	Filename  string
	Encoding  string
	Expiry    time.Duration
	Duration  time.Duration
	Transport *http.Transport
}

type CNIPList struct {
	URL       *url.URL
	Filename  string
	Expiry    time.Duration
	Duration  time.Duration
	Transport *http.Transport
}

type Filter struct {
	Config
	Store                storage.Store
	IndexFilesEnabled    bool
	IndexServerName      string
	IndexFiles           []string
	IndexFilesSet        map[string]struct{}
	ProxyPacCache        lrucache.Cache
	GFWListEnabled       bool
	CNIPListEnabled      bool
	GFWList              *GFWList
	CNIPList             *CNIPList
	CNIPListRule         filters.RoundTripFilter
	CNIPListIPNets       []*net.IPNet
	CNIPListResolver     *helpers.Resolver
	CNIPListCache        lrucache.Cache
	MobileConfigEnabled  bool
	IPHTMLEnabled        bool
	IPHTMLWhiteList      *helpers.HostMatcher
	BlackListEnabled     bool
	BlackListSiteMatcher *helpers.HostMatcher
	SiteFiltersEnabled   bool
	SiteFiltersRules     *helpers.HostMatcher
	RegionFiltersEnabled bool
	RegionFiltersRules   map[string]filters.RoundTripFilter
	RegionFiltersIPRules map[string]filters.RoundTripFilter
	RegionResolver       *helpers.Resolver
	RegionLocator        *ip17mon.Locator
	RegionFilterCache    lrucache.Cache
}

func init() {
	mime.AddExtensionType(".crt", "application/x-x509-ca-cert")
	mime.AddExtensionType(".mobileconfig", "application/x-apple-aspen-config")

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

func NewFilter(config *Config) (_ filters.Filter, err error) {
	var gfwlist GFWList
	var cniplist CNIPList

	gfwlist.Encoding = config.GFWList.Encoding
	gfwlist.Filename = config.GFWList.File
	gfwlist.Expiry = time.Duration(config.GFWList.Expiry) * time.Second
	gfwlist.Duration = time.Duration(config.GFWList.Duration) * time.Second
	gfwlist.URL, err = url.Parse(config.GFWList.URL)
	if err != nil {
		return nil, err
	}

	store := storage.LookupStoreByFilterName(filterName)
	if err != nil {
		return nil, err
	}

	if _, err := store.Head(gfwlist.Filename); err != nil {
		return nil, err
	}

	cniplist.Filename = config.CNIPList.File
	cniplist.Expiry = time.Duration(config.CNIPList.Expiry) * time.Second
	cniplist.Duration = time.Duration(config.CNIPList.Duration) * time.Second
	cniplist.URL, err = url.Parse(config.CNIPList.URL)
	if err != nil {
		return nil, err
	}

	if _, err := store.Head(cniplist.Filename); err != nil {
		return nil, err
	}

	f := &Filter{
		Config:               *config,
		Store:                store,
		IndexFilesEnabled:    config.IndexFiles.Enabled,
		IndexServerName:      config.IndexFiles.ServerName,
		IndexFiles:           config.IndexFiles.Files,
		IndexFilesSet:        make(map[string]struct{}),
		ProxyPacCache:        lrucache.NewLRUCache(32),
		GFWListEnabled:       config.GFWList.Enabled,
		CNIPListEnabled:      config.CNIPList.Enabled,
		MobileConfigEnabled:  config.MobileConfig.Enabled,
		IPHTMLEnabled:        config.IPHTML.Enabled,
		BlackListEnabled:     config.BlackList.Enabled,
		BlackListSiteMatcher: helpers.NewHostMatcher(config.BlackList.SiteRules),
		GFWList:              &gfwlist,
		CNIPList:             &cniplist,
		SiteFiltersEnabled:   config.SiteFilters.Enabled,
		RegionFiltersEnabled: config.RegionFilters.Enabled,
	}

	d0 := &net.Dialer{
		KeepAlive: 30 * time.Second,
		Timeout:   8 * time.Second,
		// DualStack: true,
	}

	d := &helpers.Dialer{
		Dialer: d0,
		Resolver: &helpers.Resolver{
			LRUCache: lrucache.NewLRUCache(32),
		},
		Level: 1,
	}

	if f.GFWListEnabled {
		d1 := d
		if config.GFWList.EnableRemoteDNS {
			d1.Resolver.DNSServer = net.ParseIP(config.GFWList.DNSServer)
			if d1.Resolver.DNSServer == nil {
				glog.Fatalf("net.ParseIP(%+v) failed: %s", config.GFWList.DNSServer, err)
			}
		}
		d1.Resolver.DNSExpiry = time.Duration(config.GFWList.Duration*2) * time.Second

		f.GFWList.Transport = &http.Transport{
			Dial: d1.Dial,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				ClientSessionCache: tls.NewLRUClientSessionCache(1000),
			},
			TLSHandshakeTimeout: 4 * time.Second,
		}

		if config.GFWList.Proxy.Enabled {
			fixedURL1, err := url.Parse(config.GFWList.Proxy.URL)
			if err != nil {
				glog.Fatalf("url.Parse(%#v) error: %s", config.GFWList.Proxy.URL, err)
			}

			dialer1, err := proxy.FromURL(fixedURL1, d1, nil)
			if err != nil {
				glog.Fatalf("proxy.FromURL(%#v) error: %s", fixedURL1.String(), err)
			}

			f.GFWList.Transport.Dial = dialer1.Dial
			f.GFWList.Transport.DialTLS = nil
			f.GFWList.Transport.Proxy = nil
		}

		go pacOnceUpdater.Do(f.pacUpdater)
	}

	if f.CNIPListEnabled {
		d2 := d
		if config.CNIPList.EnableRemoteDNS {
			d2.Resolver.DNSServer = net.ParseIP(config.CNIPList.DNSServer)
			if d2.Resolver.DNSServer == nil {
				glog.Fatalf("net.ParseIP(%+v) failed: %s", config.CNIPList.DNSServer, err)
			}
		}
		d2.Resolver.DNSExpiry = time.Duration(config.CNIPList.Duration*2) * time.Second
		f.CNIPListResolver = d2.Resolver
		f.CNIPListResolver.LRUCache = lrucache.NewLRUCache(1000)

		f.CNIPList.Transport = &http.Transport{
			Dial: d2.Dial,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				ClientSessionCache: tls.NewLRUClientSessionCache(1000),
			},
			TLSHandshakeTimeout: 4 * time.Second,
		}

		if config.CNIPList.Proxy.Enabled {
			fixedURL2, err := url.Parse(config.CNIPList.Proxy.URL)
			if err != nil {
				glog.Fatalf("url.Parse(%#v) error: %s", config.CNIPList.Proxy.URL, err)
			}

			dialer2, err := proxy.FromURL(fixedURL2, d2, nil)
			if err != nil {
				glog.Fatalf("proxy.FromURL(%#v) error: %s", fixedURL2.String(), err)
			}

			f.CNIPList.Transport.Dial = dialer2.Dial
			f.CNIPList.Transport.DialTLS = nil
			f.CNIPList.Transport.Proxy = nil
		}

		f.CNIPListIPNets, err = f.legallyParseIPNetList(f.CNIPList.Filename)
		if err != nil {
			glog.Fatalf("AUTOPROXY: legallyParseIPNetList error: %v", err)
		}

		name := config.CNIPList.Rule
		if name == "" {
			name = "direct"
		}
		f0, err := filters.GetFilter(name)
		if err != nil {
			glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) for CNIPList.Rule error: %v", name, err)
		}
		f1, ok := f0.(filters.RoundTripFilter)
		if !ok {
			glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) return %T, not a RoundTripFilter", name, f0)
		}
		f.CNIPListRule = f1
		f.CNIPListCache = lrucache.NewLRUCache(4096)

		go cniplistOnceUpdater.Do(f.cniplistUpdater)
	}

	for _, name := range f.IndexFiles {
		f.IndexFilesSet[name] = struct{}{}
	}

	if f.IPHTMLEnabled {
		f.IPHTMLWhiteList = helpers.NewHostMatcher(config.IPHTML.WhiteList)
	}

	if f.SiteFiltersEnabled {
		fm := make(map[string]interface{})
		for host, name := range config.SiteFilters.Rules {
			f0, err := filters.GetFilter(name)
			if err != nil {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) for %#v error: %v", name, host, err)
			}
			if _, ok := f0.(filters.RoundTripFilter); !ok {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) return %T, not a RoundTripFilter", name, f0)
			}
			fm[host] = f0
		}
		f.SiteFiltersRules = helpers.NewHostMatcherWithValue(fm)
	}

	if f.RegionFiltersEnabled {
		resp, err := store.Get(f.Config.RegionFilters.DataFile)
		if err != nil {
			glog.Fatalf("AUTOPROXY: store.Get(%#v) error: %v", f.Config.RegionFilters.DataFile, err)
		}
		defer resp.Body.Close()

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			glog.Fatalf("AUTOPROXY: ioutil.ReadAll(%#v) error: %v", resp.Body, err)
		}

		f.RegionLocator = ip17mon.NewLocatorWithData(data)

		f.RegionResolver = &helpers.Resolver{}
		if config.RegionFilters.EnableRemoteDNS {
			f.RegionResolver.DNSServer = net.ParseIP(config.RegionFilters.DNSServer)
			if f.RegionResolver.DNSServer == nil {
				glog.Fatalf("AUTOPROXY: net.ParseIP(%+v) failed", config.RegionFilters.DNSServer)
			}
		}

		fm := make(map[string]filters.RoundTripFilter)
		for region, name := range config.RegionFilters.Rules {
			if name == "" {
				continue
			}
			f0, err := filters.GetFilter(name)
			if err != nil {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) for %#v error: %v", name, region, err)
			}
			f1, ok := f0.(filters.RoundTripFilter)
			if !ok {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) return %T, not a RoundTripFilter", name, f0)
			}
			fm[strings.ToLower(region)] = f1
		}
		f.RegionFiltersRules = fm

		fm = make(map[string]filters.RoundTripFilter)
		for ip, name := range config.RegionFilters.IPRules {
			if name == "" {
				fm[ip] = nil
				continue
			}
			f0, err := filters.GetFilter(name)
			if err != nil {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) for %#v error: %v", name, ip, err)
			}
			f1, ok := f0.(filters.RoundTripFilter)
			if !ok {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) return %T, not a RoundTripFilter", name, f0)
			}
			fm[ip] = f1
		}
		f.RegionFiltersIPRules = fm

		f.RegionFilterCache = lrucache.NewLRUCache(uint(f.Config.RegionFilters.DNSCacheSize))
	}

	return f, nil
}

func (f *Filter) FilterName() string {
	return filterName
}

func (f *Filter) FindCountryByIP(ip string) (string, error) {
	li, err := f.RegionLocator.Find(ip)
	if err != nil {
		return "", err
	}

	//FIXME: Who should be ashamed?
	switch li.Country {
	case "中国":
		switch li.Region {
		case "台湾", "香港":
			li.Country = li.Region
		}
	}

	return li.Country, nil
}

func (f *Filter) Request(ctx context.Context, req *http.Request) (context.Context, *http.Request, error) {
	if strings.HasPrefix(req.RequestURI, "/") {
		return ctx, req, nil
	}

	host := helpers.GetHostName(req)

	if f.BlackListEnabled {
		if f.BlackListSiteMatcher.Match(host) {
			glog.V(2).Infof("%s \"AUTOPROXY BlackList %s %s %s\"", req.RemoteAddr, req.Method, req.URL.String(), req.Proto)
			return ctx, filters.DummyRequest, nil
		}
	}

	if f.SiteFiltersEnabled {
		if f1, ok := f.SiteFiltersRules.Lookup(host); ok {
			glog.V(2).Infof("%s \"AUTOPROXY SiteFilters %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
			filters.SetRoundTripFilter(ctx, f1.(filters.RoundTripFilter))
			return ctx, req, nil
		}
	}

	if f.CNIPListEnabled {
		if f1, ok := f.CNIPListCache.Get(host); ok {
			if f1 != nil {
				glog.V(2).Infof("%s \"AUTOPROXY CNIPList %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
				filters.SetRoundTripFilter(ctx, f1.(filters.RoundTripFilter))
				return ctx, req, nil
			}
		} else if ips, err := f.CNIPListResolver.LookupIP(host); err == nil && len(ips) > 0 {
			ip := ips[0]
			if ipInIPNetList(ip, f.CNIPListIPNets) {
				rule := f.CNIPListRule
				glog.V(2).Infof("%s \"AUTOPROXY CNIPList %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, rule)
				f.CNIPListCache.Set(host, rule, time.Now().Add(time.Hour))
				filters.SetRoundTripFilter(ctx, rule)
				return ctx, req, nil
			}
		}
	}

	if f.RegionFiltersEnabled {
		if f1, ok := f.RegionFilterCache.Get(host); ok {
			if f1 != nil {
				filters.SetRoundTripFilter(ctx, f1.(filters.RoundTripFilter))
			}
		} else if ips, err := f.RegionResolver.LookupIP(host); err == nil && len(ips) > 0 {
			ip := ips[0]

			if ip.IsLoopback() && !(strings.Contains(host, ".local") || strings.Contains(host, "localhost.")) {
				glog.V(2).Infof("%s \"AUTOPROXY RegionFilters BYPASS Loopback %s %s %s\" with nil", req.RemoteAddr, req.Method, req.URL.String(), req.Proto)
				f.RegionFilterCache.Set(host, nil, time.Now().Add(time.Hour))
			} else if ip.To4() == nil {
				if f1, ok := f.RegionFiltersRules["ipv6"]; ok {
					glog.V(2).Infof("%s \"AUTOPROXY RegionFilters IPv6 %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
					f.RegionFilterCache.Set(host, f1, time.Now().Add(time.Hour))
					filters.SetRoundTripFilter(ctx, f1)
				}
			} else if f1, ok := f.RegionFiltersIPRules[ip.String()]; ok {
				glog.V(2).Infof("%s \"AUTOPROXY RegionFilters IPRules %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
				f.RegionFilterCache.Set(host, f1, time.Now().Add(time.Hour))
				filters.SetRoundTripFilter(ctx, f1)
			} else if country, err := f.FindCountryByIP(ip.String()); err == nil {
				if f1, ok := f.RegionFiltersRules[country]; ok {
					glog.V(2).Infof("%s \"AUTOPROXY RegionFilters %s %s %s %s\" with %T", req.RemoteAddr, country, req.Method, req.URL.String(), req.Proto, f1)
					f.RegionFilterCache.Set(host, f1, time.Now().Add(time.Hour))
					filters.SetRoundTripFilter(ctx, f1)
				} else if f1, ok := f.RegionFiltersRules["default"]; ok {
					glog.V(2).Infof("%s \"AUTOPROXY RegionFilters Default %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
					f.RegionFilterCache.Set(host, f1, time.Now().Add(time.Hour))
					filters.SetRoundTripFilter(ctx, f1)
				} else {
					f.RegionFilterCache.Set(host, nil, time.Now().Add(time.Hour))
				}
			}
		}
	}

	return ctx, req, nil
}

func (f *Filter) RoundTrip(ctx context.Context, req *http.Request) (context.Context, *http.Response, error) {
	if f := filters.GetRoundTripFilter(ctx); f != nil {
		return f.RoundTrip(ctx, req)
	}

	switch {
	case f.SiteFiltersEnabled && req.URL.Scheme == "https":
		if f1, ok := f.SiteFiltersRules.Lookup(helpers.GetHostName(req)); ok && f1 != nil {
			return f1.(filters.RoundTripFilter).RoundTrip(ctx, req)
		}
	case f.CNIPListEnabled && req.URL.Scheme == "https":
		if f1, ok := f.CNIPListCache.Get(helpers.GetHostName(req)); ok && f1 != nil {
			return f1.(filters.RoundTripFilter).RoundTrip(ctx, req)
		}
	case f.RegionFiltersEnabled && req.URL.Scheme == "https":
		if f1, ok := f.RegionFilterCache.Get(helpers.GetHostName(req)); ok && f1 != nil {
			return f1.(filters.RoundTripFilter).RoundTrip(ctx, req)
		}
	}

	if f.IndexFilesEnabled {
		if (req.URL.Host == "" && req.RequestURI[0] == '/') || (f.IndexServerName != "" && req.Host == f.IndexServerName) {
			if _, ok := f.IndexFilesSet[req.URL.Path[1:]]; ok || req.URL.Path == "/" {
				switch {
				case f.GFWListEnabled && strings.HasSuffix(req.URL.Path, ".pac"):
					glog.V(2).Infof("%s \"AUTOPROXY ProxyPac %s %s %s\" - -", req.RemoteAddr, req.Method, req.RequestURI, req.Proto)
					return f.ProxyPacRoundTrip(ctx, req)
				case f.MobileConfigEnabled && strings.HasSuffix(req.URL.Path, ".mobileconfig"):
					glog.V(2).Infof("%s \"AUTOPROXY ProxyMobileConfig %s %s %s\" - -", req.RemoteAddr, req.Method, req.RequestURI, req.Proto)
					return f.ProxyMobileConfigRoundTrip(ctx, req)
				case f.IPHTMLEnabled && req.URL.Path == "/ip.html":
					glog.V(2).Infof("%s \"AUTOPROXY IPHTML %s %s %s\" - -", req.RemoteAddr, req.Method, req.RequestURI, req.Proto)
					return f.IPHTMLRoundTrip(ctx, req)
				default:
					glog.V(2).Infof("%s \"AUTOPROXY IndexFiles %s %s %s\" - -", req.RemoteAddr, req.Method, req.RequestURI, req.Proto)
					return f.IndexFilesRoundTrip(ctx, req)
				}
			}
		}
	}

	return ctx, nil, nil
}
