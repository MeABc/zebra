package socksproxy

import (
	"net/http"

	"../common/filters"
	"../common/helpers"
)

type Handler struct {
	Listener         helpers.Listener
	RequestFilters   []filters.RequestFilter
	RoundTripFilters []filters.RoundTripFilter
	ResponseFilters  []filters.ResponseFilter
	Branding         string
}

func (h Handler) ServeSocks(rw http.ResponseWriter, req *http.Request) {

}
