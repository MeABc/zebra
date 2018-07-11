package autoproxy

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"../../storage"
	"github.com/MeABc/glog"
)

func domainMatchList(d string, cd *CNDomainListDomains) bool {
	if d == "" {
		return false
	}

	cd.mu.RLock()
	defer cd.mu.RUnlock()

	for _, domain := range cd.Domains {
		if domain == domain || strings.HasSuffix(d, "."+domain) {
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
		return nil, fmt.Errorf("f.Store.Get(%v) error: %v", filename, err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll(%#v) error: %v", resp.Body, err)
	}

	for _, v := range bytes.Split(data, []byte("\n")) {
		domain = string(v)
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
			continue
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			glog.Warningf("ioutil.ReadAll(%T) error: %v", resp.Body, err)
			resp.Body.Close()
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
