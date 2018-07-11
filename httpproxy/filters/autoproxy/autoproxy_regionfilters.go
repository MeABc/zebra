package autoproxy

import (
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MeABc/glog"
	"github.com/cloudflare/golibs/lrucache"
	"github.com/tidwall/gjson"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

type IPinfoHandler struct {
	m            sync.Map     // map[LimiterKey]*rate.Limiter
	keyURL       atomic.Value // string
	lenURL       int
	URLs         map[string]string
	Cache        lrucache.Cache
	CacheTTL     time.Duration
	Singleflight *singleflight.Group
	Transport    *http.Transport
	RateLimit    int
	UserAgent    string
}

func (h *IPinfoHandler) InitIPinfoHandler() {
	h.lenURL = len(h.URLs)
	for k := range h.URLs {
		h.keyURL.Store(k)
		break
	}
}

func (h *IPinfoHandler) ToggleUrl() {
	m := h.keyURL.Load().(string)
	for k := range h.URLs {
		if k != m {
			h.keyURL.Store(k)
		}
	}
}

func (f *Filter) FindCountryByIP(ip string) (string, error) {
	country, err := f.RegionLocator.IPinfo(ip)
	if err != nil {
		return "", err
	}

	switch country {
	case "China", "china", "cn", "CN":
		country = "中国"
	}

	return country, nil
}

func (h *IPinfoHandler) IPinfo(ip string) (string, error) {
	country := ""
	if v, ok := h.Cache.GetNotStale(ip); ok {
		country = v.(string)
		return country, nil
	}

	if ip0 := net.ParseIP(ip); ip0 != nil {
		if ip1, ok := IsReservedIP(ip0); ok {
			switch ip1 {
			case "Host":
				country = "本机地址"
			case "Private network":
				country = "局域网"
			case "Subnet", "Reserved IP addresses":
				country = "保留地址"
			}
			h.Cache.Set(ip, country, time.Now().Add(h.CacheTTL))
			return country, nil
		}
	}

	limitKey := h.keyURL.Load().(string)
	v, ok := h.m.Load(limitKey)
	if !ok {
		v, _ = h.m.LoadOrStore(limitKey, rate.NewLimiter(rate.Limit(h.RateLimit), h.RateLimit))
	}

	limiter := v.(*rate.Limiter)
	if h.lenURL == 1 {
		r := limiter.ReserveN(time.Now(), 1)
		s := r.Delay()
		time.Sleep(s)
	} else {
		if !limiter.Allow() {
			h.ToggleUrl()
		}
	}

	country, err := h.ipinfoSearch(ip)
	if err != nil {
		return country, err
	}
	h.Cache.Set(ip, country, time.Now().Add(h.CacheTTL))

	return country, nil
}

func (h *IPinfoHandler) ipinfoSearch(ipStr string) (string, error) {
	country := ""
	u0 := h.keyURL.Load().(string)
	url := strings.Replace(u0, "%s", ipStr, 1)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return country, err
	}

	req.Header.Set("User-Agent", h.UserAgent)

	v, err, shared := h.Singleflight.Do(url, func() (interface{}, error) {
		return h.Transport.RoundTrip(req)
	})
	if err != nil {
		return country, err
	}

	resp := v.(*http.Response)
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return country, err
	}

	rule, _ := h.URLs[u0]
	switch rule {
	case "normal":
		country = gjson.GetBytes(data, "country").String()
	case "taobao":
		country = gjson.GetBytes(data, "data.country").String()
	}

	h.Singleflight.Forget(url)

	glog.V(3).Infof("AUTOPROXY RegionFilters ipinfoSearch %s country result: %s, shared result: %t", url, country, shared)

	return country, nil
}

// see https://en.wikipedia.org/wiki/Reserved_IP_addresses
func IsReservedIP(ip net.IP) (string, bool) {
	if ip4 := ip.To4(); ip4 != nil {
		switch ip4[0] {
		case 10:
			return "Private network", true
		case 100:
			if ip4[1] >= 64 && ip4[1] <= 127 {
				return "Private network", true
			}
		case 127:
			return "Host", true
		case 169:
			if ip4[1] == 254 {
				return "Subnet", true
			}
		case 172:
			if ip4[1] >= 16 && ip4[1] <= 31 {
				return "Private network", true
			}
		case 192:
			switch ip4[1] {
			case 0:
				switch ip4[2] {
				case 0, 2:
					return "Private network", true
				}
			case 18, 19:
				return "Private network", true
			case 51:
				if ip4[2] == 100 {
					return "Reserved IP addresses", true
				}
			case 88:
				if ip4[2] == 99 {
					return "Reserved IP addresses", true
				}
			case 168:
				return "Private network", true
			}
		case 203:
			if ip4[1] == 0 && ip4[2] == 113 {
				return "Reserved IP addresses", true
			}
		case 224:
			return "Reserved IP addresses", true
		case 240:
			return "Reserved IP addresses", true
		}
	}
	return "", false
}

// https://github.com/phuslu/apiserver
// https://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93
func IsPoisonousChinaIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	switch ip4[0] {
	case 42:
		return ip4[1] == 123 && ip4[2] == 125 && ip4[3] == 237 // 42.123.125.237
	case 60:
		return ip4[1] == 19 && ip4[2] == 29 && ip4[3] == 22 // 60.19.29.22
	case 61:
		switch ip4[1] {
		case 54:
			return ip4[2] == 28 && ip4[3] == 6 // 61.54.28.6
		case 131:
			switch ip4[2] {
			case 208:
				switch ip4[3] {
				case 210, 211: // 61.131.208.210, 61.131.208.211
					return true
				}
			}
		}
	case 110:
		return ip4[1] == 249 && ip4[2] == 209 && ip4[3] == 42 // 110.249.209.42
	case 113:
		return ip4[1] == 11 && ip4[2] == 194 && ip4[3] == 190 // 113.11.194.190
	case 120:
		return ip4[1] == 192 && ip4[2] == 83 && ip4[3] == 163 // 120.192.83.163
	case 123:
		switch ip4[1] {
		case 126:
			return ip4[2] == 249 && ip4[3] == 238 // 123.126.249.238
		case 129:
			switch ip4[2] {
			case 254:
				switch ip4[3] {
				case 12, 13, 14, 15: // 123.129.254.12, 123.129.254.13, 123.129.254.14, 123.129.254.15
					return true
				}
			}
		}
	case 125:
		return ip4[1] == 211 && ip4[2] == 213 && ip4[3] == 132 // 125.211.213.132
	case 183:
		return ip4[1] == 221 && ip4[2] == 250 && ip4[3] == 11 // 183.221.250.11
	case 202:
		switch ip4[1] {
		case 98:
			switch ip4[2] {
			case 24:
				switch ip4[3] {
				case 122, 124, 125: // 202.98.24.122, 202.98.24.124, 202.98.24.125
					return true
				}
			}
		case 106:
			return ip4[2] == 1 && ip4[3] == 2 // 202.106.1.2
		case 181:
			return ip4[2] == 7 && ip4[3] == 85 // 202.181.7.85
		}
	case 211:
		switch ip4[1] {
		case 138:
			switch ip4[2] {
			case 34:
				return ip4[3] == 204 // 211.138.34.204
			case 74:
				return ip4[3] == 132 // 211.138.74.132
			}
		case 94:
			return ip4[2] == 66 && ip4[3] == 147 // 211.94.66.147
		case 98:
			switch ip4[2] {
			case 70:
				switch ip4[3] {
				case 195, 226, 227: // 211.98.70.195, 211.98.70.225, 211.98.70.227
					return true
				}
			case 71:
				return ip4[3] == 195 // 211.98.71.195
			}
		}
	case 218:
		return ip4[1] == 93 && ip4[2] == 250 && ip4[3] == 18 // 218.93.250.18
	case 220:
		switch ip4[1] {
		case 165:
			switch ip4[2] {
			case 8:
				switch ip4[3] {
				case 172, 174: // 220.165.8.172, 220.165.8.174
					return true
				}
			}
		case 250:
			return ip4[2] == 64 && ip4[3] == 20 // 220.250.64.20
		}
	case 221:
		switch ip4[1] {
		case 8:
			return ip4[2] == 69 && ip4[3] == 27 // 221.8.69.27
		case 179:
			return ip4[2] == 46 && ip4[3] == 190 // 221.179.46.190
		}
	}
	return false
}
