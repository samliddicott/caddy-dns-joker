package caddydnsjoker

import (
	"time"

	"github.com/libdns/libdns"
)

// ToLibDNS converts libdns.RR to libdns.Record interface (here we use RR directly)
func ToLibDNS(rr libdns.RR) libdns.Record {
	return &rr
}

// FromLibDNS converts libdns.Record to libdns.RR
func FromLibDNS(r libdns.Record) libdns.RR {
	return r.RR()
}

// Helper to convert slices
func ToLibDNSRecords(rrs []libdns.RR) []libdns.Record {
	res := make([]libdns.Record, len(rrs))
	for i, rr := range rrs {
		res[i] = ToLibDNS(rr)
	}
	return res
}

func FromLibDNSRecords(records []libdns.Record) []libdns.RR {
	res := make([]libdns.RR, len(records))
	for i, r := range records {
		res[i] = FromLibDNS(r)
	}
	return res
}

// Make a RR
func Record(name, typ, data string, ttl time.Duration) libdns.RR {
	return libdns.RR{
		Name: name,
		Type: typ,
		Data: data,
		TTL:  ttl,
	}
}
