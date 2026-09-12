package main

import (
	"testing"

	"github.com/miekg/dns"
)

func TestIsAcceptableUpstreamResponse(t *testing.T) {
	cases := []struct {
		name  string
		rcode int
		want  bool
	}{
		{name: "success", rcode: dns.RcodeSuccess, want: true},
		{name: "nxdomain", rcode: dns.RcodeNameError, want: true},
		{name: "servfail", rcode: dns.RcodeServerFailure, want: false},
		{name: "refused", rcode: dns.RcodeRefused, want: false},
		{name: "formerr", rcode: dns.RcodeFormatError, want: false},
	}

	if isAcceptableUpstreamResponse(nil) {
		t.Fatal("nil response must not be accepted")
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: tc.rcode}}
			if got := isAcceptableUpstreamResponse(msg); got != tc.want {
				t.Fatalf("rcode %d: expected %v, got %v", tc.rcode, tc.want, got)
			}
		})
	}
}
