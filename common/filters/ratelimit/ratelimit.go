package auth

import (
	"context"
	"net/http"

	"github.com/MeABc/glog"

	"../../filters"
	"../../helpers"
	"../../storage"
)

const (
	filterName string = "ratelimit"
)

type Config struct {
	Threshold int
	Rate      int
	Capacity  int
}

type Filter struct {
	Config
	Threshold int64
	Rate      float64
	Capacity  int64
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
	f := &Filter{
		Config:    *config,
		Threshold: int64(config.Threshold),
		Capacity:  int64(config.Capacity),
		Rate:      float64(config.Rate),
	}

	if config.Capacity <= 0 {
		f.Capacity = int64(config.Rate) * 1024
	}

	return f, nil
}

func (f *Filter) FilterName() string {
	return filterName
}

func (f *Filter) Response(ctx context.Context, resp *http.Response) (context.Context, *http.Response, error) {

	if f.Rate > 0 && resp.ContentLength > f.Threshold {
		glog.V(2).Infof("RateLimit %#v rate to %#v", resp.Request.URL.String(), f.Rate)
		resp.Body = helpers.NewRateLimitReader(resp.Body, f.Rate, f.Capacity)
	}

	return ctx, resp, nil
}
