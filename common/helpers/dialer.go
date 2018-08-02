package helpers

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/MeABc/glog"
)

type Dialer struct {
	Dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}

	Resolver *Resolver
	Level    int
}

func (d *Dialer) Dial(network, address string) (conn net.Conn, err error) {
	glog.V(3).Infof("Dail(%#v, %#v)", network, address)

	switch network {
	case "tcp", "tcp4", "tcp6":
		if d.Resolver != nil {
			if host, port, err := net.SplitHostPort(address); err == nil {
				if ips, err := d.Resolver.LookupIP(host); err == nil {
					if len(ips) == 0 {
						return nil, net.InvalidAddrError(fmt.Sprintf("Invaid DNS Record: %s", address))
					}
					return d.dialMulti(network, address, ips, port)
				}
			}
		}
	}

	return d.Dialer.DialContext(context.Background(), network, address)
}

func (d *Dialer) dialMulti(network, address string, ips []net.IP, port string) (conn net.Conn, err error) {
	if d.Level <= 1 || len(ips) == 1 {
		for i, ip := range ips {
			addr := net.JoinHostPort(ip.String(), port)
			conn, err := d.Dialer.DialContext(context.Background(), network, addr)
			if err != nil {
				if i < len(ips)-1 {
					continue
				} else {
					return nil, err
				}
			}
			return conn, nil
		}
	} else {
		type racer struct {
			c net.Conn
			e error
		}

		level := len(ips)
		if level > d.Level {
			level = d.Level
			ips = ips[:level]
		}

		lane := make(chan racer, level)
		for i := 0; i < level; i++ {
			go func(addr string, c chan<- racer) {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()

				conn, err := d.Dialer.DialContext(ctx, network, addr)
				lane <- racer{conn, err}
			}(net.JoinHostPort(ips[i].String(), port), lane)
		}

		var r racer
		for j := 0; j < level; j++ {
			r = <-lane
			if r.e == nil {
				go func(c chan racer) {
					for r1 := range lane {
						if r1.c != nil {
							r1.c.Close()
						}
					}
					close(lane)
				}(lane)
				return r.c, nil
			}
		}
		close(lane)
	}

	return nil, net.UnknownNetworkError("Unkown transport/direct error")
}
