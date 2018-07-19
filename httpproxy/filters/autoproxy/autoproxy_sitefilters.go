package autoproxy

import (
	"net/http"
	"strings"

	"github.com/MeABc/glog"

	"../../filters"
	"../../helpers"
)

func (f *Filter) SiteFiltersInit(config *Config) {
	if f.SiteFiltersEnabled {
		siteFiltersStrings := make(map[string]string)
		siteFiltersSuffixs := make(map[string]string)
		siteFiltersMatcherRules := make(map[string]string)
		for site, name := range config.SiteFilters.Rules {
			if strings.Contains(site, "/") {
				if strings.HasSuffix(site, "$") {
					siteFiltersSuffixs[site] = name
				} else {
					siteFiltersStrings[site] = name
				}
			} else {
				siteFiltersMatcherRules[site] = name
			}
		}

		fm0 := make(map[string]filters.RoundTripFilter)
		for site, name := range siteFiltersStrings {
			f0, err := filters.GetFilter(name)
			if err != nil {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) for %#v error: %v", name, site, err)
			}
			f1, ok := f0.(filters.RoundTripFilter)
			if !ok {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) return %T, not a RoundTripFilter", name, f0)
			}
			fm0[site] = f1
		}
		f.SiteFiltersStrings = fm0

		fm1 := make(map[string]filters.RoundTripFilter)
		for site, name := range siteFiltersSuffixs {
			f0, err := filters.GetFilter(name)
			if err != nil {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) for %#v error: %v", name, site, err)
			}
			f1, ok := f0.(filters.RoundTripFilter)
			if !ok {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) return %T, not a RoundTripFilter", name, f0)
			}
			fm1[site] = f1
		}
		f.SiteFiltersSuffixs = fm1

		fm2 := make(map[string]interface{})
		for host, name := range siteFiltersMatcherRules {
			f0, err := filters.GetFilter(name)
			if err != nil {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) for %#v error: %v", name, host, err)
			}
			if _, ok := f0.(filters.RoundTripFilter); !ok {
				glog.Fatalf("AUTOPROXY: filters.GetFilter(%#v) return %T, not a RoundTripFilter", name, f0)
			}
			fm2[host] = f0
		}
		f.SiteFiltersRules = helpers.NewHostMatcherWithValue(fm2)
	}
}

func (f *Filter) SiteFiltersMatcher(
	host string,
	req *http.Request,
) (interface{}, bool) {
	if f1, ok := f.SiteFiltersRules.Lookup(host); ok && f1 != nil {
		return f1, ok
	}

	u := req.URL.String()
	if len(f.SiteFiltersSuffixs) > 0 {
		for s := range f.SiteFiltersSuffixs {
			if strings.HasSuffix(u, s) {
				if f1, ok := f.SiteFiltersSuffixs[s]; ok {
					return f1, ok
				}
			}
		}
	}
	if len(f.SiteFiltersStrings) > 0 {
		for s := range f.SiteFiltersStrings {
			if strings.Contains(u, s) {
				if f1, ok := f.SiteFiltersStrings[s]; ok {
					return f1, ok
				}
			}
		}
	}

	return nil, false
}
