package sni

import (
	"context"
	"net/http"

	"github.com/MeABc/glog"

	"../../filters"
	"../../helpers"
	"../../storage"
)

const (
	filterName string = "sni"
)

type Config struct {
	SNIServers         []string
	RedirectServerName map[string]string
	Transport          struct {
		Dialer struct {
			SocketReadBuffer int
			KeepAlive        int
			Level            int
			Timeout          int
		}
		Proxy struct {
			Enabled bool
			URL     string
		}
		DisableKeepAlives     bool
		IdleConnTimeout       int
		MaxIdleConnsPerHost   int
		ResponseHeaderTimeout int
	}
}

type Filter struct {
	Config
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
	d := &helpers.Dialer{}

	tr := &http.Transport{
		Dial: d.Dial,
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

	return ctx, nil, nil
}
