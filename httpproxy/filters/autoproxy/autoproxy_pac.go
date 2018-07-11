package autoproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MeABc/glog"

	"../../storage"
)

const (
	localhost2 string = "127.0.1.2"
)

func (f *Filter) ProxyPacRoundTrip(ctx context.Context, req *http.Request) (context.Context, *http.Response, error) {
	_, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		port = "80"
	}

	if v, ok := f.ProxyPacCache.Get(req.URL.Path); ok {
		if s, ok := v.(string); ok {
			s = fixProxyPac(s, req)
			return ctx, &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{},
				Request:       req,
				Close:         true,
				ContentLength: int64(len(s)),
				Body:          ioutil.NopCloser(strings.NewReader(s)),
			}, nil
		}
	}

	filename := req.URL.Path[1:]

	buf := new(bytes.Buffer)

	resp, err := f.Store.Get(filename)
	if os.IsNotExist(err) || resp.StatusCode == http.StatusNotFound {
		glog.V(2).Infof("AUTOPROXY ProxyPac: generate %#v", filename)
		s := fmt.Sprintf(`// User-defined FindProxyForURL
var whiteList = new Array(
	// "ruanyifeng.com",
);
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "169.254.0.0", "255.255.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "127.0.0.0", "255.255.255.0") ||
        shExpMatch(host, "*.local") ||
        shExpMatch(host, 'localhost.*')) {
        return 'DIRECT';
    }

    if (shExpMatch(host, '*.google*.*')) {
        return 'PROXY %s:%s';
    }

    return 'DIRECT';
}
`, localhost2, port)

		f.Store.Put(filename, http.Header{}, ioutil.NopCloser(bytes.NewBufferString(s)))

		if resp.Body != nil {
			resp.Body.Close()
		}
	}
	if err != nil {
		return ctx, nil, err
	}

	if resp, err := f.Store.Get(filename); err == nil {
		defer resp.Body.Close()
		if b, err := ioutil.ReadAll(resp.Body); err == nil {
			if f.GFWListEnabled {
				b = []byte(strings.Replace(string(b), "function FindProxyForURL(", "function MyFindProxyForURL(", 1))
			}
			buf.Write(b)
		}
	}

	if f.GFWListEnabled {
		f.GFWListDomains.mu.RLock()
		io.WriteString(buf, "\nvar sites = {\n")
		for _, site := range f.GFWListDomains.Domains {
			io.WriteString(buf, "\""+site+"\":1,\n")
		}
		f.GFWListDomains.mu.RUnlock()
		io.WriteString(buf, "\"google.com\":1\n")
		io.WriteString(buf, "}\n")

		io.WriteString(buf, `
for (i in whiteList) {
	delete sites[whiteList[i]];
}
function FindProxyForURL(url, host) {
    if ((p = MyFindProxyForURL(url, host)) != "DIRECT") {
        return p
    }

    var lastPos;
    do {
        if (sites.hasOwnProperty(host)) {
            return 'PROXY `+localhost2+`:8087';
        }
        lastPos = host.indexOf('.') + 1;
        host = host.slice(lastPos);
    } while (lastPos >= 1);
    return 'DIRECT';
}`)
	}

	s := buf.String()
	f.ProxyPacCache.Set(req.URL.Path, s, time.Now().Add(15*time.Minute))

	s = fixProxyPac(s, req)
	resp = &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		Request:       req,
		Close:         true,
		ContentLength: int64(len(s)),
		Body:          ioutil.NopCloser(strings.NewReader(s)),
	}

	return ctx, resp, nil
}

func (f *Filter) pacUpdater() {
	// glog.V(2).Infof("start updater for %+v, expiry=%s, duration=%s", f.GFWList.URL.String(), f.GFWList.Expiry, f.GFWList.Duration)

	ticker := time.Tick(f.GFWList.Duration)
	var r io.Reader

	for {
		select {
		case <-ticker:
			glog.V(2).Infof("Begin auto gfwlist(%#v) update...", f.GFWList.URL.String())
			resp, err := f.Store.Head(f.GFWList.Filename)
			if err != nil {
				glog.Warningf("stat gfwlist(%#v) err: %v", f.GFWList.Filename, err)
				continue
			}

			lm := resp.Header.Get("Last-Modified")
			if lm == "" {
				glog.Warningf("gfwlist(%#v) header(%#v) does not contains last-modified", f.GFWList.Filename, resp.Header)
				continue
			}

			modTime, err := time.Parse(storage.DateFormat, lm)
			if err != nil {
				glog.Warningf("stat gfwlist(%#v) has parse %#v error: %v", f.GFWList.Filename, lm, err)
				continue
			}

			if time.Now().Sub(modTime) < f.GFWList.Expiry {
				glog.V(2).Infof("gfwlist has not updated. update expiry: %v", f.GFWList.Expiry)
				continue
			}
		}

		glog.Infof("Downloading %#v", f.GFWList.URL.String())

		req, err := http.NewRequest(http.MethodGet, f.GFWList.URL.String(), nil)
		if err != nil {
			glog.Warningf("NewRequest(%#v) error: %v", f.GFWList.URL.String(), err)
			continue
		}

		resp, err := f.GFWList.Transport.RoundTrip(req)
		if err != nil {
			glog.Warningf("%T.RoundTrip(%#v) error: %v", f.GFWList.Transport, f.GFWList.URL.String(), err.Error())
			if resp != nil && resp.Body != nil {
				io.Copy(ioutil.Discard, resp.Body)
				resp.Body.Close()
			}
			continue
		}

		r = resp.Body
		switch f.GFWList.Encoding {
		case "base64":
			r = base64.NewDecoder(base64.StdEncoding, r)
		default:
			break
		}

		data, err := ioutil.ReadAll(r)
		if err != nil {
			glog.Warningf("ioutil.ReadAll(%T) error: %v", r, err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		_, err = f.Store.Delete(f.GFWList.Filename)
		if err != nil {
			glog.Warningf("%T.DeleteObject(%#v) error: %v", f.Store, f.GFWList.Filename, err)
			continue
		}

		_, err = f.Store.Put(f.GFWList.Filename, http.Header{}, ioutil.NopCloser(bytes.NewReader(data)))
		if err != nil {
			glog.Warningf("%T.PutObject(%#v) error: %v", f.Store, f.GFWList.Filename, err)
			continue
		}

		f.GFWListDomains.mu.Lock()
		f.GFWListDomains.Domains, err = f.legallyParseGFWList(f.GFWList.Filename)
		if err != nil {
			glog.Fatalf("AUTOPROXY: legallyParseGFWList error: %v", err)
		}
		f.GFWListDomains.mu.Unlock()

		f.ProxyPacCache.Clear()

		glog.Infof("Update %#v from %#v OK", f.GFWList.Filename, f.GFWList.URL.String())
	}
}

func fixProxyPac(s string, req *http.Request) string {
	r := regexp.MustCompile(`PROXY ` + localhost2 + `:\d+`)
	return r.ReplaceAllString(s, "PROXY "+req.Host)
}

func parseAutoProxy(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)

	sites := make(map[string]struct{}, 0)

	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())

		if s == "" ||
			strings.HasPrefix(s, "[") ||
			strings.HasPrefix(s, "!") ||
			strings.HasPrefix(s, "||!") ||
			strings.HasPrefix(s, "@@") {
			continue
		}

		switch {
		case strings.HasPrefix(s, "||"):
			site := strings.Split(s[2:], "/")[0]
			switch {
			case strings.Contains(site, "*."):
				parts := strings.Split(site, "*.")
				site = parts[len(parts)-1]
			case strings.HasPrefix(site, "*"):
				parts := strings.SplitN(site, ".", 2)
				site = parts[len(parts)-1]
			}
			sites[site] = struct{}{}
		case strings.HasPrefix(s, "|http://"):
			if u, err := url.Parse(s[1:]); err == nil {
				site := u.Host
				switch {
				case strings.Contains(site, "*."):
					parts := strings.Split(site, "*.")
					site = parts[len(parts)-1]
				case strings.HasPrefix(site, "*"):
					parts := strings.SplitN(site, ".", 2)
					site = parts[len(parts)-1]
				}
				sites[site] = struct{}{}
			}
		case strings.HasPrefix(s, "."):
			site := strings.Split(strings.Split(s[1:], "/")[0], "*")[0]
			if strings.HasSuffix(site, ".co") {
				site += "m"
			}
			sites[site] = struct{}{}
		case !strings.ContainsAny(s, "*"):
			site := strings.Split(s, "/")[0]
			if regexp.MustCompile(`^[a-zA-Z0-9\.\_\-]+$`).MatchString(site) {
				sites[site] = struct{}{}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sites1 := make([]string, 0)
	for s := range sites {
		sites1 = append(sites1, s)
	}

	return sites1, nil
}

// parse gfwlist.txt to GFWList
func (f *Filter) legallyParseGFWList(filename string) ([]string, error) {
	resp, err := f.Store.Get(filename)
	if err != nil {
		glog.Errorf("GetObject(%#v) error: %v", filename, err)
		return nil, err
	}
	defer resp.Body.Close()

	sites, err := parseAutoProxy(resp.Body)
	if err != nil {
		glog.Errorf("parseAutoProxy(%#v) error: %v", filename, err)
		return nil, err
	}

	sort.Strings(sites)

	return sites, nil
}

func GFWListDomainsMatch(d string, cd *GFWListDomains) bool {
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

func NewGFWListDomains() *GFWListDomains {
	g := &GFWListDomains{
		Domains: nil,
	}
	return g
}
