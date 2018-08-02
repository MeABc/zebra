package autoproxy

import (
	"context"
	"mime"
	"net"
	"net/http"
	"net/url"
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
	filterName string = "autoproxy"
)

type Config struct {
	SiteFilters struct {
		Enabled bool
		Rules   map[string]string
	}
	CNDomainList struct {
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
		URLs            map[string]string
		EnableRemoteDNS bool
		DNSServer       string
		DNSCacheSize    int
		Duration        int
		Proxy           struct {
			Enabled bool
			URL     string
		}
		UserAgent string
		Rules     map[string]string
		IPRules   map[string]string
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
		Filter struct {
			Enabled bool
			Rule    string
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
	Hosts map[string]string
}

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

type CNDomainList struct {
	URL       *url.URL
	Filename  string
	Expiry    time.Duration
	Duration  time.Duration
	Transport *http.Transport
}

type CNIPListIPNets struct {
	mu     sync.RWMutex
	IPNets []*net.IPNet
}

type CNDomainListDomains struct {
	mu      sync.RWMutex
	Domains []string
}

type GFWListDomains struct {
	mu      sync.RWMutex
	Domains []string
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
	GFWListFilterEnabled bool
	CNIPListEnabled      bool
	CNDomainListEnabled  bool
	GFWList              *GFWList
	GFWListDomains       *GFWListDomains
	GFWListFilterCache   lrucache.Cache
	GFWListFilterRule    filters.RoundTripFilter
	CNIPList             *CNIPList
	CNDomainList         *CNDomainList
	CNDomainListRule     filters.RoundTripFilter
	CNDomainListCache    lrucache.Cache
	CNDomainListDomains  *CNDomainListDomains
	CNDomainListResolver *helpers.Resolver
	CNIPListRule         filters.RoundTripFilter
	CNIPListIPNets       *CNIPListIPNets
	CNIPListResolver     *helpers.Resolver
	CNIPListCache        lrucache.Cache
	MobileConfigEnabled  bool
	IPHTMLEnabled        bool
	IPHTMLWhiteList      *helpers.HostMatcher
	BlackListEnabled     bool
	BlackListSiteMatcher *helpers.HostMatcher
	SiteFiltersEnabled   bool
	SiteFiltersStrings   map[string]filters.RoundTripFilter
	SiteFiltersSuffixs   map[string]filters.RoundTripFilter
	SiteFiltersRules     *helpers.HostMatcher
	RegionFiltersEnabled bool
	RegionFiltersRules   map[string]filters.RoundTripFilter
	RegionFiltersIPRules map[string]filters.RoundTripFilter
	RegionResolver       *helpers.Resolver
	RegionLocator        *IPinfoHandler
	RegionFilterCache    lrucache.Cache
	RegionFiltersURLsLen int
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
	var cndomainlist CNDomainList

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

	cndomainlist.Filename = config.CNDomainList.File
	cndomainlist.Expiry = time.Duration(config.CNDomainList.Expiry) * time.Second
	cndomainlist.Duration = time.Duration(config.CNDomainList.Duration) * time.Second
	cndomainlist.URL, err = url.Parse(config.CNDomainList.URL)
	if err != nil {
		return nil, err
	}

	if _, err := store.Head(cndomainlist.Filename); err != nil {
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
		GFWListFilterEnabled: config.GFWList.Filter.Enabled,
		CNIPListEnabled:      config.CNIPList.Enabled,
		CNDomainListEnabled:  config.CNDomainList.Enabled,
		MobileConfigEnabled:  config.MobileConfig.Enabled,
		IPHTMLEnabled:        config.IPHTML.Enabled,
		BlackListEnabled:     config.BlackList.Enabled,
		BlackListSiteMatcher: helpers.NewHostMatcher(config.BlackList.SiteRules),
		GFWList:              &gfwlist,
		CNIPList:             &cniplist,
		CNDomainList:         &cndomainlist,
		SiteFiltersEnabled:   config.SiteFilters.Enabled,
		RegionFiltersEnabled: config.RegionFilters.Enabled,
	}

	for _, name := range f.IndexFiles {
		f.IndexFilesSet[name] = struct{}{}
	}

	if f.IPHTMLEnabled {
		f.IPHTMLWhiteList = helpers.NewHostMatcher(config.IPHTML.WhiteList)
	}

	f.GFWListInit(config)

	f.CNIPListInit(config)

	f.CNDomainListInit(config)

	f.SiteFiltersInit(config)

	f.RegionfiltersInit(config)

	return f, nil
}

func (f *Filter) FilterName() string {
	return filterName
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
		if f1, ok := f.SiteFiltersMatcher(host, req); ok && f1 != nil {
			glog.V(2).Infof("%s \"AUTOPROXY SiteFilters %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
			filters.SetRoundTripFilter(ctx, f1.(filters.RoundTripFilter))
			return ctx, req, nil
		}
	}

	if f.CNDomainListEnabled {
		if f1, ok := f.CNDomainListCache.Get(host); ok && f1 != nil {
			glog.V(3).Infof("%s \"AUTOPROXY CNDomainList Cache %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
			filters.SetRoundTripFilter(ctx, f1.(filters.RoundTripFilter))
			return ctx, req, nil
		}
		if domainMatchList(host, f.CNDomainListDomains) {
			rule := f.CNDomainListRule
			glog.V(2).Infof("%s \"AUTOPROXY CNDomainList %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, rule)
			f.CNDomainListCache.Set(host, rule, time.Now().Add(time.Hour))
			filters.SetRoundTripFilter(ctx, rule)
			return ctx, req, nil
		}
	}

	if f.GFWListEnabled && f.GFWListFilterEnabled {
		if f1, ok := f.GFWListFilterCache.Get(host); ok && f1 != nil {
			glog.V(3).Infof("%s \"AUTOPROXY GFWFilter Cache %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
			filters.SetRoundTripFilter(ctx, f1.(filters.RoundTripFilter))
			return ctx, req, nil
		}
		if GFWListDomainsMatch(host, f.GFWListDomains) {
			rule := f.GFWListFilterRule
			glog.V(2).Infof("%s \"AUTOPROXY GFWFilter %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, rule)
			f.GFWListFilterCache.Set(host, rule, time.Now().Add(time.Hour))
			filters.SetRoundTripFilter(ctx, rule)
			return ctx, req, nil
		}
	}

	if f.CNIPListEnabled {
		if f1, ok := f.CNIPListCache.Get(host); ok && f1 != nil {
			glog.V(3).Infof("%s \"AUTOPROXY CNIPList Cache %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
			filters.SetRoundTripFilter(ctx, f1.(filters.RoundTripFilter))
			return ctx, req, nil
		}
		if ips, err := f.CNIPListResolver.LookupIP(host); err == nil && len(ips) > 0 {
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
		if f1, ok := f.RegionFilterCache.Get(host); ok && f1 != nil {
			glog.V(3).Infof("%s \"AUTOPROXY RegionFilters Cache %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
			filters.SetRoundTripFilter(ctx, f1.(filters.RoundTripFilter))
			return ctx, req, nil
		}
		if ips, err := f.RegionResolver.LookupIP(host); err == nil && len(ips) > 0 {
			ip := ips[0]
			if ip.IsLoopback() && !(strings.Contains(host, ".local") || strings.Contains(host, "localhost.")) {
				glog.V(2).Infof("%s \"AUTOPROXY RegionFilters BYPASS Loopback %s %s %s\" with nil", req.RemoteAddr, req.Method, req.URL.String(), req.Proto)
				f.RegionFilterCache.Set(host, nil, time.Now().Add(time.Hour))
			}
			if ip.To4() == nil {
				if f1, ok := f.RegionFiltersRules["ipv6"]; ok {
					glog.V(2).Infof("%s \"AUTOPROXY RegionFilters IPv6 %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
					f.RegionFilterCache.Set(host, f1, time.Now().Add(time.Hour))
					filters.SetRoundTripFilter(ctx, f1)
					return ctx, req, nil
				}
			}
			if f1, ok := f.RegionFiltersIPRules[ip.String()]; ok {
				glog.V(2).Infof("%s \"AUTOPROXY RegionFilters IPRules %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
				f.RegionFilterCache.Set(host, f1, time.Now().Add(time.Hour))
				filters.SetRoundTripFilter(ctx, f1)
				return ctx, req, nil
			}
			if country, err := f.FindCountryByIP(ip.String()); err == nil && country != "" {
				if f1, ok := f.RegionFiltersRules[country]; ok {
					glog.V(2).Infof("%s \"AUTOPROXY RegionFilters %s %s %s %s\" with %T", req.RemoteAddr, country, req.Method, req.URL.String(), req.Proto, f1)
					f.RegionFilterCache.Set(host, f1, time.Now().Add(time.Hour))
					filters.SetRoundTripFilter(ctx, f1)
					return ctx, req, nil
				}
				if f1, ok := f.RegionFiltersRules["default"]; ok {
					glog.V(2).Infof("%s \"AUTOPROXY RegionFilters Default %s %s %s\" with %T", req.RemoteAddr, req.Method, req.URL.String(), req.Proto, f1)
					f.RegionFilterCache.Set(host, f1, time.Now().Add(time.Hour))
					filters.SetRoundTripFilter(ctx, f1)
					return ctx, req, nil
				}
				f.RegionFilterCache.Set(host, nil, time.Now().Add(time.Hour))
			}
		}
	}

	return ctx, req, nil
}

func (f *Filter) RoundTrip(ctx context.Context, req *http.Request) (context.Context, *http.Response, error) {
	if f := filters.GetRoundTripFilter(ctx); f != nil {
		return f.RoundTrip(ctx, req)
	}

	host := helpers.GetHostName(req)

	glog.V(3).Infof("%s \"AUTOPROXY RoundTrip %s %s %s %s %s\" - -", req.RemoteAddr, req.URL.Scheme, host, req.Method, req.RequestURI, req.Proto)

	if f.SiteFiltersEnabled {
		if f1, ok := f.SiteFiltersMatcher(host, req); ok && f1 != nil {
			return f1.(filters.RoundTripFilter).RoundTrip(ctx, req)
		}
	}
	if f.CNDomainListEnabled {
		if f1, ok := f.CNDomainListCache.Get(host); ok && f1 != nil {
			return f1.(filters.RoundTripFilter).RoundTrip(ctx, req)
		}
	}
	if f.GFWListEnabled && f.GFWListFilterEnabled {
		if f1, ok := f.GFWListFilterCache.Get(host); ok && f1 != nil {
			return f1.(filters.RoundTripFilter).RoundTrip(ctx, req)
		}
	}
	if f.CNIPListEnabled {
		if f1, ok := f.CNIPListCache.Get(host); ok && f1 != nil {
			return f1.(filters.RoundTripFilter).RoundTrip(ctx, req)
		}
	}
	if f.RegionFiltersEnabled {
		if f1, ok := f.RegionFilterCache.Get(host); ok && f1 != nil {
			return f1.(filters.RoundTripFilter).RoundTrip(ctx, req)
		}
	}

	if f.IndexFilesEnabled {
		if (req.URL.Host == "" && req.RequestURI[0] == '/') || (f.IndexServerName != "" && req.Host == f.IndexServerName) {
			if _, ok := f.IndexFilesSet[req.URL.Path[1:]]; ok || req.URL.Path == "/" {
				if f.GFWListEnabled && strings.HasSuffix(req.URL.Path, ".pac") {
					glog.V(2).Infof("%s \"AUTOPROXY ProxyPac %s %s %s\" - -", req.RemoteAddr, req.Method, req.RequestURI, req.Proto)
					return f.ProxyPacRoundTrip(ctx, req)
				}
				if f.MobileConfigEnabled && strings.HasSuffix(req.URL.Path, ".mobileconfig") {
					glog.V(2).Infof("%s \"AUTOPROXY ProxyMobileConfig %s %s %s\" - -", req.RemoteAddr, req.Method, req.RequestURI, req.Proto)
					return f.ProxyMobileConfigRoundTrip(ctx, req)
				}
				if f.IPHTMLEnabled && req.URL.Path == "/ip.html" {
					glog.V(2).Infof("%s \"AUTOPROXY IPHTML %s %s %s\" - -", req.RemoteAddr, req.Method, req.RequestURI, req.Proto)
					return f.IPHTMLRoundTrip(ctx, req)
				}
				glog.V(2).Infof("%s \"AUTOPROXY IndexFiles %s %s %s\" - -", req.RemoteAddr, req.Method, req.RequestURI, req.Proto)
				return f.IndexFilesRoundTrip(ctx, req)
			}
		}
	}

	return ctx, nil, nil
}
