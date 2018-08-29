package helpers

import (
	"crypto/tls"
	"fmt"
)

func TLSVersion(name string) uint16 {
	switch name {
	case "TLS13", "TLSv1.3", "TLSv13":
		return tls.VersionTLS13
	case "TLS12", "TLSv1.2", "TLSv12":
		return tls.VersionTLS12
	case "TLS11", "TLSv1.1", "TLSv11":
		return tls.VersionTLS11
	case "TLS1", "TLSv1.0", "TLSv10":
		return tls.VersionTLS10
	case "SSL3", "SSLv3.0", "SSLv30":
		return tls.VersionSSL30
	case "Q043":
		return 43
	case "Q039":
		return 39
	}
	return 0
}

func TLSVersionName(value uint16) string {
	switch value {
	case tls.VersionTLS13, tls.VersionTLS13Draft28:
		return "TLSv13"
	case tls.VersionTLS12:
		return "TLSv12"
	case tls.VersionTLS11:
		return "TLSv11"
	case tls.VersionTLS10:
		return "TLSv1"
	case 43:
		return "Q043"
	case 39:
		return "Q039"
	}
	return fmt.Sprintf("0x%x", value)
}

func TLSMaxVersion(Versions []uint16) uint16 {
	var tls13D28, tls13, tls12, tls11, tls10 bool
	for _, value := range Versions {
		switch value {
		case tls.VersionTLS13Draft28:
			tls13D28 = true
		case tls.VersionTLS13:
			tls13 = true
		case tls.VersionTLS12:
			tls12 = true
		case tls.VersionTLS11:
			tls11 = true
		case tls.VersionTLS10:
			tls10 = true
		}
	}

	if tls13D28 {
		return tls.VersionTLS13Draft28
	}
	if tls13 {
		return tls.VersionTLS13
	}
	if tls12 {
		return tls.VersionTLS12
	}
	if tls11 {
		return tls.VersionTLS11
	}
	if tls10 {
		return tls.VersionTLS10
	}

	return tls.VersionTLS12
}

func TLSMinVersion(Versions []uint16) uint16 {
	var tls13D28, tls13, tls12, tls11, tls10 bool
	for _, value := range Versions {
		switch value {
		case tls.VersionTLS13Draft28:
			tls13D28 = true
		case tls.VersionTLS13:
			tls13 = true
		case tls.VersionTLS12:
			tls12 = true
		case tls.VersionTLS11:
			tls11 = true
		case tls.VersionTLS10:
			tls10 = true
		}
	}

	if tls10 {
		return tls.VersionTLS10
	}
	if tls11 {
		return tls.VersionTLS11
	}
	if tls12 {
		return tls.VersionTLS12
	}
	if tls13 {
		return tls.VersionTLS13
	}
	if tls13D28 {
		return tls.VersionTLS13Draft28
	}

	return tls.VersionTLS10
}
