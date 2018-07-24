package helpers

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/MeABc/glog"
	"github.com/cloudflare/golibs/lrucache"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

const (
	DefaultDNSCacheExpiry time.Duration = 600 * time.Second
	DefaultDNSDialTimeout time.Duration = 5 * time.Second
)

type Resolver struct {
	Singleflight *singleflight.Group
	LRUCache     lrucache.Cache
	BlackList    lrucache.Cache
	Hosts        lrucache.Cache
	DNSServer    string
	DNSExpiry    time.Duration
	DisableIPv6  bool
	ForceIPv6    bool
	Network      string // name of the network ("tcp", "tcp-tls", "udp")
	EDNSEnabled  bool   // TODO : EDNS0 support
	ExternalIP   string // TODO : EDNS0 ?
}

func (r *Resolver) LookupHost(name string) ([]string, error) {
	ips, err := r.LookupIP(name)
	if err != nil {
		return nil, err
	}

	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = ip.String()
	}

	return addrs, nil
}

func (r *Resolver) LookupIP(name string) ([]net.IP, error) {
	if r.Hosts != nil {
		if v, ok := r.Hosts.GetQuiet(name); ok {
			switch v.(type) {
			case []net.IP:
				return v.([]net.IP), nil
			case string:
				if ip := net.ParseIP(v.(string)); ip != nil {
					h := []net.IP{ip}
					r.Hosts.Set(name, h, time.Time{})
					return h, nil
				}
				return nil, fmt.Errorf("LookupIP: net.ParseIP(%s) failed", name)
			default:
				return nil, fmt.Errorf("LookupIP: cannot convert %T(%+v) to []net.IP", v, v)
			}
		}
	}

	if r.LRUCache != nil {
		if v, ok := r.LRUCache.GetNotStale(name); ok {
			switch v.(type) {
			case []net.IP:
				return v.([]net.IP), nil
			case string:
				name = v.(string)
			default:
				return nil, fmt.Errorf("LookupIP: cannot convert %T(%+v) to []net.IP", v, v)
			}
		}
	}

	v, err, shared := r.Singleflight.Do(name, func() (interface{}, error) {
		return r.lookupIP0(name)
	})
	ips := v.([]net.IP)
	if err == nil {
		li := len(ips)
		if r.BlackList != nil && li > 0 {
			ips1 := ips[:0]
			for _, ip := range ips {
				if _, ok := r.BlackList.GetQuiet(ip.String()); !ok {
					ips1 = append(ips1, ip)
				}
			}
			ips = ips1
		}

		if r.LRUCache != nil && li > 0 {
			if r.DNSExpiry == 0 {
				r.LRUCache.Set(name, ips, time.Now().Add(DefaultDNSCacheExpiry))
			} else {
				r.LRUCache.Set(name, ips, time.Now().Add(r.DNSExpiry))
			}
		}
	}

	r.Singleflight.Forget(name)

	glog.V(2).Infof("LookupIP(%#v) return %+v, err=%+v, shared result: %t", name, ips, err, shared)

	return ips, err
}

func (r *Resolver) lookupIP0(name string) ([]net.IP, error) {
	if ip := net.ParseIP(name); ip != nil {
		return []net.IP{ip}, nil
	}

	lookupIP := r.lookupIP1
	if r.DNSServer != "" {
		lookupIP = r.lookupIP2
	}

	return lookupIP(name)
}

func (r *Resolver) lookupIP1(name string) ([]net.IP, error) {
	ips, err := LookupIP(name)
	if err != nil {
		return nil, err
	}

	ips1 := ips[:0]
	for _, ip := range ips {
		if strings.Contains(ip.String(), ":") {
			if r.ForceIPv6 || !r.DisableIPv6 {
				ips1 = append(ips1, ip)
			}
		} else {
			if !r.ForceIPv6 {
				ips1 = append(ips1, ip)
			}
		}
	}

	return ips1, nil
}

func (r *Resolver) lookupIP2(name string) ([]net.IP, error) {
	c := &dns.Client{
		Timeout: DefaultDNSDialTimeout,
	}
	switch r.Network {
	case "udp", "":
		c.Net = "udp"
	case "tcp":
		c.Net = "tcp"
	case "tcp-tls":
		c.Net = "tcp-tls"
	default:
		c.Net = "udp"
	}
	m := &dns.Msg{}

	switch {
	case r.ForceIPv6:
		m.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	case r.DisableIPv6:
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	default:
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	}

	ip0, port0, _, err := ParseIPPort(r.DNSServer)
	if err != nil {
		return nil, err
	}
	if port0 == "" {
		port0 = "53"
	}

	reply, _, err := c.Exchange(m, net.JoinHostPort(ip0.String(), port0))
	if err != nil {
		return nil, err
	}

	if len(reply.Answer) < 1 {
		return nil, fmt.Errorf("no Answer from dns server %v", r.DNSServer)
	}

	ips := make([]net.IP, 0, 4)
	var ip net.IP

	for _, rr := range reply.Answer {
		switch rr.(type) {
		case *dns.AAAA:
			ip = rr.(*dns.AAAA).AAAA
		case *dns.A:
			ip = rr.(*dns.A).A
		}
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	return ips, nil
}

// https://rosettacode.org/wiki/Parse_an_IP_Address#Go
func ParseIPPort(s string) (ip net.IP, port, space string, err error) {
	ip = net.ParseIP(s)
	if ip == nil {
		var host string
		host, port, err = net.SplitHostPort(s)
		if err != nil {
			return
		}
		if port != "" {
			// This check only makes sense if service names are not allowed
			if _, err = strconv.ParseUint(port, 10, 16); err != nil {
				return
			}
		}
		ip = net.ParseIP(host)
	}
	if ip == nil {
		err = errors.New("invalid address format")
	} else {
		space = "IPv6"
		if ip4 := ip.To4(); ip4 != nil {
			space = "IPv4"
			ip = ip4
		}
	}
	return
}
