package autoproxy

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"../../storage"
	"github.com/MeABc/glog"
)

func ipInIPNetList(ip net.IP, ipnets *CNIPListIPNets) bool {
	if ip == nil {
		return false
	}

	ipnets.mu.RLock()
	defer ipnets.mu.RUnlock()

	for _, ipNet := range ipnets.IPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// parse china_ip_list.txt to IPNet list
func (f *Filter) legallyParseIPNetList(filename string) ([]*net.IPNet, error) {
	var ipNets []*net.IPNet

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
		_, ipn, err := net.ParseCIDR(string(v))
		if err != nil {
			return nil, fmt.Errorf("legallyParseIPNetList error: %v", err)
		}
		ipNets = append(ipNets, ipn)
	}
	if len(ipNets) == 0 {
		return nil, fmt.Errorf("empty IP Network list")
	}

	return ipNets, nil
}

func (f *Filter) cniplistUpdater() {
	// glog.V(2).Infof("start updater for %+v, expiry=%s, duration=%s", f.CNIPList.URL.String(), f.CNIPList.Expiry, f.CNIPList.Duration)

	ticker := time.Tick(f.CNIPList.Duration)

	for {
		select {
		case <-ticker:
			glog.V(2).Infof("Begin auto china_ip_list(%#v) update...", f.CNIPList.URL.String())
			resp, err := f.Store.Head(f.CNIPList.Filename)
			if err != nil {
				glog.Warningf("stat cniplist(%#v) err: %v", f.CNIPList.Filename, err)
				continue
			}

			lm := resp.Header.Get("Last-Modified")
			if lm == "" {
				glog.Warningf("cniplist(%#v) header(%#v) does not contains last-modified", f.CNIPList.Filename, resp.Header)
				continue
			}

			modTime, err := time.Parse(storage.DateFormat, lm)
			if err != nil {
				glog.Warningf("stat cniplist(%#v) has parse %#v error: %v", f.CNIPList.Filename, lm, err)
				continue
			}

			if time.Now().Sub(modTime) < f.CNIPList.Expiry {
				glog.V(2).Infof("cniplist has not updated. update expiry: %v", f.CNIPList.Expiry)
				continue
			}
		}

		glog.Infof("Downloading %#v", f.CNIPList.URL.String())

		req, err := http.NewRequest(http.MethodGet, f.CNIPList.URL.String(), nil)
		if err != nil {
			glog.Warningf("NewRequest(%#v) error: %v", f.CNIPList.URL.String(), err)
			continue
		}

		resp, err := f.CNIPList.Transport.RoundTrip(req)
		if err != nil {
			glog.Warningf("%T.RoundTrip(%#v) error: %v", f.CNIPList.Transport, f.CNIPList.URL.String(), err.Error())
			continue
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			glog.Warningf("ioutil.ReadAll(%T) error: %v", resp.Body, err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		_, err = f.Store.Delete(f.CNIPList.Filename)
		if err != nil {
			glog.Warningf("%T.DeleteObject(%#v) error: %v", f.Store, f.CNIPList.Filename, err)
			continue
		}

		_, err = f.Store.Put(f.CNIPList.Filename, http.Header{}, ioutil.NopCloser(bytes.NewReader(data)))
		if err != nil {
			glog.Warningf("%T.PutObject(%#v) error: %v", f.Store, f.CNIPList.Filename, err)
			continue
		}

		f.CNIPListIPNets.mu.Lock()
		f.CNIPListIPNets.IPNets, err = f.legallyParseIPNetList(f.CNIPList.Filename)
		if err != nil {
			glog.Fatalf("AUTOPROXY: legallyParseIPNetList error: %v", err)
		}
		f.CNIPListIPNets.mu.Unlock()

		f.CNIPListCache.Clear()

		glog.Infof("Update %#v from %#v OK", f.CNIPList.Filename, f.CNIPList.URL.String())
	}
}
