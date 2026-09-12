package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCoalesceUpstreamLookup(t *testing.T) {
	const callers = 8

	rt := &runtimeConfig{}
	var calls atomic.Int32
	var startedOnce sync.Once
	started := make(chan struct{})
	release := make(chan struct{})
	ready := make(chan struct{}, callers)
	begin := make(chan struct{})

	type result struct {
		id  uint16
		msg *dns.Msg
	}
	results := make(chan result, callers)

	lookup := func() *dns.Msg {
		calls.Add(1)
		startedOnce.Do(func() { close(started) })
		<-release
		return &dns.Msg{MsgHdr: dns.MsgHdr{Id: 999, Rcode: dns.RcodeSuccess}}
	}

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			ready <- struct{}{}
			<-begin
			msg := coalesceUpstreamLookup(rt, "example.com.:1:1", lookup)
			msg.Id = id
			results <- result{id: id, msg: msg}
		}(uint16(i + 1))
	}

	for i := 0; i < callers; i++ {
		<-ready
	}
	close(begin)
	<-started
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)

	if got := calls.Load(); got != 1 {
		t.Fatalf("expected one upstream lookup, got %d", got)
	}

	seen := make(map[uint16]*dns.Msg, callers)
	for item := range results {
		if item.msg == nil {
			t.Fatal("expected DNS response")
		}
		if item.msg.Id != item.id {
			t.Fatalf("expected response ID %d, got %d", item.id, item.msg.Id)
		}
		seen[item.id] = item.msg
	}
	if len(seen) != callers {
		t.Fatalf("expected %d responses, got %d", callers, len(seen))
	}
}

func TestCoalesceUpstreamLookupFailure(t *testing.T) {
	rt := &runtimeConfig{}
	if got := coalesceUpstreamLookup(rt, "failed", func() *dns.Msg { return nil }); got != nil {
		t.Fatal("expected nil response")
	}
}
