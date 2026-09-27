package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"time"
)

// checkPprofAddr accepts only 127.0.0.1:PORT. The profiling endpoints
// expose heap contents and can stall the process, so they must never be
// reachable from the network.
func checkPprofAddr(addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || ap.Addr() != netip.MustParseAddr("127.0.0.1") {
		return fmt.Errorf("-pprof %q: must be 127.0.0.1:PORT (profiling is never served on other addresses)", addr)
	}
	return nil
}

// servePprof serves net/http/pprof on addr until stop is called. It
// listens before returning, so a port in use fails at startup.
func servePprof(addr string, stderr io.Writer) (stop func(), err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("-pprof: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "ids: pprof:", err)
		}
	}()
	fmt.Fprintf(stderr, "ids: pprof on http://%s/debug/pprof/\n", ln.Addr())
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}, nil
}
