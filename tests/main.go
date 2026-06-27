// PQC API Test Harness
// Requires Go 1.24+ — X25519MLKEM768 is enabled by default in crypto/tls.
// No external dependencies needed for hybrid TLS.
//
// Usage:
//   go run main.go -ca ./certs/ca.crt -base https://localhost:8443 -pdf ./sample.pdf
//
// Flags:
//   -base    Base URL of the API server (default: https://localhost:8443)
//   -ca      Path to the CA certificate (PEM) used by the server
//   -pdf     Path to a PDF file to use in document signing tests
//   -n       Number of iterations for each benchmark (default: 100)
//   -user    Test username (default: testuser)
//   -pass    Test password (default: testpass123)

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config

var (
	baseURL  = flag.String("base", "https://localhost:8443", "API base URL")
	caPath   = flag.String("ca", "./certs/ca.crt", "Path to CA certificate (PEM)")
	pdfPath  = flag.String("pdf", "./sample.pdf", "Path to PDF file for signing tests")
	n        = flag.Int("n", 100, "Number of iterations for each benchmark")
	username = flag.String("user", "testuser_harness", "Test username")
	password = flag.String("pass", "testpass123!", "Test password")

	// Resource-measurement flags. The handshake benchmark can drive concurrent
	// workers and sample the server container's CPU/memory via cgroup counters,
	// so the post-quantum TLS cost can be attributed precisely.
	concurrency = flag.Int("concurrency", 1, "Concurrent workers for the TLS handshake benchmark (1 = sequential)")
	container   = flag.String("container", "pqc_api", "Docker container name of the API server (for CPU/mem sampling via cgroup)")
	// When running the harness inside WSL while Docker runs on the Windows host,
	// the docker CLI may only be reachable as "docker.exe" via WSL interop. Set
	// -docker docker.exe in that case.
	dockerCmd = flag.String("docker", "docker", "Docker CLI to invoke for cgroup sampling (e.g. docker.exe from WSL)")
	// Interleaving alternates PQC/classical handshakes in small blocks so both
	// configs see identical background load — the CPU delta then cancels drift
	// instead of comparing two separate multi-second windows.
	interleave = flag.Bool("interleave", true, "Interleave PQC/classical handshakes in alternating blocks (cancels background CPU drift)")
	block      = flag.Int("block", 50, "Handshakes per block when interleaving (larger = less docker-exec overhead, coarser interleaving)")
)

// MEtrics

type Result struct {
	Name     string
	Samples  []time.Duration
	Failures int

	// Handshake byte counts (only set for handshake benchmarks). These record
	// the raw bytes on the wire during the TLS handshake, before any HTTP.
	HandshakeBytesSent int64
	HandshakeBytesRecv int64
}

// countingConn wraps a net.Conn and counts the raw bytes read and written.
// By wrapping the TCP connection *before* the TLS layer is built on top of it,
// we capture the exact handshake size on the wire (key shares, certificate,
// CertificateVerify, etc.), including TLS record framing overhead.
type countingConn struct {
	net.Conn
	read    int64
	written int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read += int64(n)
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written += int64(n)
	return n, err
}

func (r *Result) Record(d time.Duration, err error) {
	if err != nil {
		r.Failures++
		return
	}
	r.Samples = append(r.Samples, d)
}

func (r *Result) Print() {
	if len(r.Samples) == 0 {
		fmt.Printf("  %-40s  NO DATA  (%d failures)\n", r.Name, r.Failures)
		return
	}
	sorted := make([]time.Duration, len(r.Samples))
	copy(sorted, r.Samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	p50 := sorted[len(sorted)*50/100]
	p95 := sorted[len(sorted)*95/100]
	p99 := sorted[len(sorted)*99/100]
	var total time.Duration
	for _, s := range sorted {
		total += s
	}
	avg := total / time.Duration(len(sorted))

	fmt.Printf("  %-40s  avg=%-8s  p50=%-8s  p95=%-8s  p99=%-8s  ok=%d  fail=%d\n",
		r.Name, avg.Round(time.Microsecond), p50.Round(time.Microsecond),
		p95.Round(time.Microsecond), p99.Round(time.Microsecond),
		len(r.Samples), r.Failures)

	if r.HandshakeBytesSent > 0 || r.HandshakeBytesRecv > 0 {
		fmt.Printf("  %-40s  total=%d bytes (sent %d / recv %d)\n",
			"  └─ handshake size",
			r.HandshakeBytesSent+r.HandshakeBytesRecv,
			r.HandshakeBytesSent, r.HandshakeBytesRecv)
	}
}

// ─── HTTP Client ──────────────────────────────────────────────────────────────

func buildClient(caPath string) *http.Client {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatalf("Cannot read CA cert %q: %v", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("Failed to parse CA cert from %q", caPath)
	}

	tlsCfg := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: true, // server cert lacks SANs — dev only
		MinVersion:         tls.VersionTLS13,
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Second,
	}
}

// handshakeSample holds the outcome of a single measured TLS handshake.
type handshakeSample struct {
	elapsed   time.Duration
	bytesSent int64 // raw bytes written during the handshake (ClientHello, etc.)
	bytesRecv int64 // raw bytes read during the handshake (ServerHello, cert, etc.)
}

// measureHandshake performs a fresh TLS handshake, pinning the key-exchange
// group to `curves`, and returns the handshake-completion time together with the
// exact number of bytes exchanged on the wire. Pinning a single curve forces the
// server to use it (the handshake fails if the server doesn't support it), which
// makes the byte counts directly attributable to that key-exchange algorithm.
func measureHandshake(addr, caPath string, curves []tls.CurveID) (handshakeSample, error) {
	var sample handshakeSample

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return sample, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	tlsCfg := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: true, // server cert lacks SANs — dev only
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   curves,
	}

	host := strings.TrimPrefix(addr, "https://")
	host = strings.TrimPrefix(host, "http://")

	// Dial raw TCP first, wrap it in the byte counter, then drive TLS on top so
	// every handshake byte passes through (and is counted by) the wrapper.
	raw, err := net.Dial("tcp", host)
	if err != nil {
		return sample, fmt.Errorf("TCP dial failed: %w", err)
	}
	cc := &countingConn{Conn: raw}
	conn := tls.Client(cc, tlsCfg)

	start := time.Now()
	err = conn.Handshake()
	sample.elapsed = time.Since(start)
	if err != nil {
		conn.Close()
		return sample, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Read counters immediately after the handshake, before any application data.
	sample.bytesSent = cc.written
	sample.bytesRecv = cc.read
	conn.Close()
	return sample, nil
}

// ─── Resource Sampling (server CPU / memory via cgroup) ─────────────────────────

// ResourceMetrics captures the server container's CPU and memory consumption
// during one handshake batch. CPU is a cumulative delta read from the cgroup
// (true CPU-seconds the server burned), memory is the peak observed during the
// batch minus the baseline. These let us attribute cost to the key-exchange
// algorithm by comparing the PQC variant against the classical one.
type ResourceMetrics struct {
	Name         string
	Iterations   int
	Concurrency  int
	OKCount      int   // successful handshakes (denominator for per-handshake cost)
	CPUUsecDelta int64 // total server CPU microseconds consumed during the batch
	MemBefore    int64 // container memory at batch start (bytes)
	MemPeak      int64 // peak container memory during the batch (bytes)
	OK           bool  // false if cgroup counters could not be read
}

// dockerExecCat cats a file inside the target container. Returns ok=false if
// docker is unavailable, the container isn't running, or the path is missing.
func dockerExecCat(container, path string) (string, bool) {
	out, err := exec.Command(*dockerCmd, "exec", container, "cat", path).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}

// readCPUUsec returns the container's cumulative CPU usage in microseconds.
// Tries cgroup v2 (cpu.stat → usage_usec) first, then falls back to cgroup v1
// (cpuacct.usage, in nanoseconds).
func readCPUUsec(container string) (int64, bool) {
	if s, ok := dockerExecCat(container, "/sys/fs/cgroup/cpu.stat"); ok {
		for _, line := range strings.Split(s, "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "usage_usec" {
				if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					return v, true
				}
			}
		}
	}
	if s, ok := dockerExecCat(container, "/sys/fs/cgroup/cpuacct/cpuacct.usage"); ok {
		if v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return v / 1000, true // ns → us
		}
	}
	return 0, false
}

// readMemCurrent returns the container's current memory usage in bytes.
// Tries cgroup v2 (memory.current) first, then cgroup v1 (memory.usage_in_bytes).
func readMemCurrent(container string) (int64, bool) {
	if s, ok := dockerExecCat(container, "/sys/fs/cgroup/memory.current"); ok {
		if v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return v, true
		}
	}
	if s, ok := dockerExecCat(container, "/sys/fs/cgroup/memory/memory.usage_in_bytes"); ok {
		if v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return v, true
		}
	}
	return 0, false
}

// sampleMemPeak polls the container memory every 20ms until stop is closed,
// then sends the peak observed value on done.
func sampleMemPeak(container string, stop <-chan struct{}, done chan<- int64) {
	var peak int64
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			done <- peak
			return
		case <-t.C:
			if m, ok := readMemCurrent(container); ok && m > peak {
				peak = m
			}
		}
	}
}

// runHandshakes drives `iterations` fresh handshakes across `concurrency`
// workers, all pinned to `curves`. Returns the per-handshake latency samples,
// the failure count, the first error seen (if any), and the on-the-wire byte
// counts from the last successful handshake (deterministic per config).
func runHandshakes(addr, caPath string, curves []tls.CurveID, iterations, concurrency int) (samples []time.Duration, failures int, firstErr error, lastSent, lastRecv int64) {
	type res struct {
		sample handshakeSample
		err    error
	}
	if concurrency < 1 {
		concurrency = 1
	}
	jobs := make(chan struct{}, iterations)
	out := make(chan res, iterations)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				s, err := measureHandshake(addr, caPath, curves)
				out <- res{s, err}
			}
		}()
	}
	for i := 0; i < iterations; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	go func() { wg.Wait(); close(out) }()

	for r := range out {
		if r.err != nil {
			failures++
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		samples = append(samples, r.sample.elapsed)
		lastSent, lastRecv = r.sample.bytesSent, r.sample.bytesRecv
	}
	return samples, failures, firstErr, lastSent, lastRecv
}

// ─── API Helpers ──────────────────────────────────────────────────────────────

type apiClient struct {
	http    *http.Client
	base    string
	token   string
}

func (c *apiClient) do(method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.http.Do(req)
}

func (c *apiClient) doJSON(method, path string, payload any) (map[string]any, int, error) {
	var bodyReader io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		bodyReader = bytes.NewReader(b)
	}
	resp, err := c.do(method, path, bodyReader, "application/json")
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result, resp.StatusCode, nil
}

func (c *apiClient) register() error {
	_, status, err := c.doJSON("POST", "/api/auth/register", map[string]string{
		"username": *username,
		"password": *password,
	})
	if err != nil {
		return err
	}
	// Accept any 2xx or 409 (already exists)
	if (status < 200 || status >= 300) && status != 409 {
		return fmt.Errorf("unexpected register status %d", status)
	}
	return nil
}

func (c *apiClient) login() error {
	result, status, err := c.doJSON("POST", "/api/auth/login", map[string]string{
		"username": *username,
		"password": *password,
	})
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("login failed: status %d, body %v", status, result)
	}
	token, ok := result["token"].(string)
	if !ok {
		return fmt.Errorf("no token in login response: %v", result)
	}
	c.token = token
	return nil
}

func (c *apiClient) logout() error {
	_, status, err := c.doJSON("POST", "/api/users/logout", nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("logout failed: status %d", status)
	}
	c.token = ""
	return nil
}

// signPDF uploads a PDF and returns (documentID, duration, error).
func (c *apiClient) signPDF(pdfBytes []byte) (string, time.Duration, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "document.pdf")
	if err != nil {
		return "", 0, err
	}
	fw.Write(pdfBytes)
	mw.Close()

	start := time.Now()
	resp, err := c.do("POST", "/api/documents/sign", &buf, mw.FormDataContentType())
	elapsed := time.Since(start)
	if err != nil {
		return "", elapsed, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return "", elapsed, fmt.Errorf("sign returned %d: %s", resp.StatusCode, body)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	// Server returns doc_id as a JSON number (float64 in Go)
	docID := fmt.Sprintf("%.0f", result["doc_id"])
	return docID, elapsed, nil
}

// downloadPDF downloads a signed PDF by ID. Returns duration of the request.
func (c *apiClient) downloadPDF(id string) ([]byte, time.Duration, error) {
	start := time.Now()
	resp, err := c.do("GET", "/api/documents/"+id+"/download", nil, "")
	elapsed := time.Since(start)
	if err != nil {
		return nil, elapsed, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, elapsed, fmt.Errorf("download returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	return data, elapsed, err
}

// getPublicKeyPEM fetches the server ML-DSA public key from GET /api/documents/public-key.
func (c *apiClient) getPublicKeyPEM() (string, error) {
	resp, err := c.do("GET", "/api/documents/public-key", nil, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	pem, _ := result["public_key_pem"].(string)
	if pem == "" {
		return "", fmt.Errorf("no public_key_pem in response: %v", result)
	}
	return pem, nil
}

// verifyPDF posts the original PDF, the base64 signature, and the PEM public key.
// The signature and public key come from a prior signPDF call and getPublicKeyPEM.
func (c *apiClient) verifyPDF(pdfBytes []byte, signatureB64, pubKeyPEM string) (bool, time.Duration, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	addFile := func(name, fname string, data []byte) error {
		fw, e := mw.CreateFormFile(name, fname)
		if e != nil {
			return e
		}
		_, e = fw.Write(data)
		return e
	}

	if err := addFile("file", "document.pdf", pdfBytes); err != nil {
		return false, 0, err
	}
	if err := addFile("signature", "signature.txt", []byte(signatureB64)); err != nil {
		return false, 0, err
	}
	if err := addFile("public_key", "pubkey.pem", []byte(pubKeyPEM)); err != nil {
		return false, 0, err
	}
	mw.Close()

	start := time.Now()
	resp, err := c.do("POST", "/api/documents/verify", &buf, mw.FormDataContentType())
	elapsed := time.Since(start)
	if err != nil {
		return false, elapsed, err
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	valid := result["status"] == "VALID" || result["valid"] == true
	return valid, elapsed, nil
}

// ─── Benchmark Suites ────────────────────────────────────────────────────────

// benchmarkHandshake measures handshake latency AND on-the-wire handshake size
// for two key-exchange configurations: the PQC hybrid (X25519MLKEM768) and the
// classical baseline (X25519). Running both makes the cost of post-quantum key
// exchange directly comparable — same server, same ECDSA certificate, only the
// KEX group differs.
func benchmarkHandshake(addr, caPath, container string, iterations, concurrency int) ([]*Result, []*ResourceMetrics) {
	variants := []struct {
		name   string
		curves []tls.CurveID
	}{
		{"TLS Handshake (X25519MLKEM768 PQC)", []tls.CurveID{tls.X25519MLKEM768}},
		{"TLS Handshake (X25519 classical)", []tls.CurveID{tls.X25519}},
	}

	var results []*Result
	var resources []*ResourceMetrics
	for _, v := range variants {
		r := &Result{Name: v.name}
		rm := &ResourceMetrics{Name: v.name, Iterations: iterations, Concurrency: concurrency}

		// Snapshot server CPU/memory just before the batch.
		cpuBefore, cpuOK := readCPUUsec(container)
		memBefore, memOK := readMemCurrent(container)

		// Track peak memory during the batch in the background.
		var stop chan struct{}
		var memDone chan int64
		if memOK {
			stop = make(chan struct{})
			memDone = make(chan int64, 1)
			go sampleMemPeak(container, stop, memDone)
		}

		samples, failures, firstErr, lastSent, lastRecv := runHandshakes(addr, caPath, v.curves, iterations, concurrency)
		if firstErr != nil {
			fmt.Printf("\n  [%s] FIRST ERROR: %v\n", v.name, firstErr)
		}
		r.Samples = samples
		r.Failures = failures
		// Handshake size is deterministic per config, so the last successful
		// sample is representative of every successful handshake.
		r.HandshakeBytesSent = lastSent
		r.HandshakeBytesRecv = lastRecv

		// Close out the resource measurement.
		var memPeak int64
		if memOK {
			close(stop)
			memPeak = <-memDone
		}
		cpuAfter, cpuOK2 := readCPUUsec(container)

		rm.OKCount = len(samples)
		rm.OK = cpuOK && cpuOK2 && memOK
		if cpuOK && cpuOK2 {
			rm.CPUUsecDelta = cpuAfter - cpuBefore
		}
		rm.MemBefore = memBefore
		rm.MemPeak = memPeak
		if rm.MemPeak < rm.MemBefore {
			rm.MemPeak = rm.MemBefore // batch too short to catch a higher sample
		}

		results = append(results, r)
		resources = append(resources, rm)
	}

	// Report the size delta between the two configurations.
	printHandshakeSizeDelta(results)

	// Report the CPU/memory delta between the two configurations.
	printResourceSummary(container, concurrency, resources)

	return results, resources
}

// printHandshakeSizeDelta reports the on-the-wire size difference between the
// PQC and classical handshake variants (results[0] = PQC, results[1] = classical).
func printHandshakeSizeDelta(results []*Result) {
	if len(results) == 2 && results[0].HandshakeBytesSent > 0 && results[1].HandshakeBytesSent > 0 {
		pqc := results[0].HandshakeBytesSent + results[0].HandshakeBytesRecv
		classical := results[1].HandshakeBytesSent + results[1].HandshakeBytesRecv
		fmt.Printf("\n  [Handshake] PQC adds %d bytes vs classical (%d vs %d, %.1fx)\n",
			pqc-classical, pqc, classical, float64(pqc)/float64(classical))
	}
}

// benchmarkHandshakeInterleaved measures the same two variants as
// benchmarkHandshake, but alternates them in small blocks. Each block is
// bracketed by a single before/after cgroup CPU read whose delta is accumulated
// per variant. Because blocks alternate finely in time — and both variants get
// the same number of blocks — background CPU drift (and the fixed per-block
// docker-exec overhead) cancels in the PQC-vs-classical delta, which the
// sequential per-variant method cannot do.
func benchmarkHandshakeInterleaved(addr, caPath, container string, iterations, concurrency, blockSize int) ([]*Result, []*ResourceMetrics) {
	variants := []struct {
		name   string
		curves []tls.CurveID
	}{
		{"TLS Handshake (X25519MLKEM768 PQC)", []tls.CurveID{tls.X25519MLKEM768}},
		{"TLS Handshake (X25519 classical)", []tls.CurveID{tls.X25519}},
	}
	if blockSize < 1 {
		blockSize = 1
	}

	type vstate struct {
		result   *Result
		rm       *ResourceMetrics
		curves   []tls.CurveID
		cpuAccum int64
		cpuFail  bool
		firstErr error
	}
	states := make([]*vstate, len(variants))
	for i, v := range variants {
		states[i] = &vstate{
			result: &Result{Name: v.name},
			rm:     &ResourceMetrics{Name: v.name, Iterations: iterations, Concurrency: concurrency},
			curves: v.curves,
		}
	}

	// Baseline memory + background peak sampler attributing each sample to the
	// currently-active variant via an atomic index.
	memBase, memOK := readMemCurrent(container)
	var memPeak [2]int64
	var active int32 = -1
	stop := make(chan struct{})
	var swg sync.WaitGroup
	if memOK {
		swg.Add(1)
		go func() {
			defer swg.Done()
			t := time.NewTicker(20 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					av := atomic.LoadInt32(&active)
					if av < 0 {
						continue
					}
					if m, ok := readMemCurrent(container); ok {
						for {
							old := atomic.LoadInt64(&memPeak[av])
							if m <= old {
								break
							}
							if atomic.CompareAndSwapInt64(&memPeak[av], old, m) {
								break
							}
						}
					}
				}
			}
		}()
	}

	remaining := []int{iterations, iterations}
	for round := 0; remaining[0] > 0 || remaining[1] > 0; round++ {
		order := []int{0, 1}
		if round%2 == 1 { // swap order each round to remove any first-in-round bias
			order = []int{1, 0}
		}
		for _, vi := range order {
			if remaining[vi] <= 0 {
				continue
			}
			b := blockSize
			if b > remaining[vi] {
				b = remaining[vi]
			}

			atomic.StoreInt32(&active, int32(vi))
			cpuBefore, ok1 := readCPUUsec(container)
			samples, failures, ferr, lastSent, lastRecv := runHandshakes(addr, caPath, states[vi].curves, b, concurrency)
			cpuAfter, ok2 := readCPUUsec(container)
			atomic.StoreInt32(&active, -1)

			st := states[vi]
			st.result.Samples = append(st.result.Samples, samples...)
			st.result.Failures += failures
			if lastSent > 0 || lastRecv > 0 {
				st.result.HandshakeBytesSent = lastSent
				st.result.HandshakeBytesRecv = lastRecv
			}
			if ferr != nil && st.firstErr == nil {
				st.firstErr = ferr
			}
			if ok1 && ok2 {
				st.cpuAccum += cpuAfter - cpuBefore
			} else {
				st.cpuFail = true
			}
			remaining[vi] -= b
		}
	}

	if memOK {
		close(stop)
		swg.Wait()
	}

	var results []*Result
	var resources []*ResourceMetrics
	for i, st := range states {
		if st.firstErr != nil {
			fmt.Printf("\n  [%s] FIRST ERROR: %v\n", st.result.Name, st.firstErr)
		}
		st.rm.OKCount = len(st.result.Samples)
		st.rm.CPUUsecDelta = st.cpuAccum
		st.rm.MemBefore = memBase
		st.rm.MemPeak = atomic.LoadInt64(&memPeak[i])
		if st.rm.MemPeak < memBase {
			st.rm.MemPeak = memBase
		}
		st.rm.OK = !st.cpuFail && memOK
		results = append(results, st.result)
		resources = append(resources, st.rm)
	}

	printHandshakeSizeDelta(results)
	fmt.Printf("  [Handshake] interleaved in blocks of %d\n", blockSize)
	printResourceSummary(container, concurrency, resources)

	return results, resources
}

// printResourceSummary prints per-variant CPU/memory cost and, when both
// variants measured cleanly, the marginal post-quantum cost per handshake.
func printResourceSummary(container string, concurrency int, resources []*ResourceMetrics) {
	fmt.Printf("\n  [Resources] container=%q  concurrency=%d\n", container, concurrency)
	for _, rm := range resources {
		if !rm.OK || rm.OKCount == 0 {
			fmt.Printf("  %-40s  (cgroup read failed — is docker on PATH and %q running?)\n", rm.Name, container)
			continue
		}
		cpuPer := float64(rm.CPUUsecDelta) / float64(rm.OKCount)
		memDelta := rm.MemPeak - rm.MemBefore
		fmt.Printf("  %-40s  cpu=%.1f us/hs  (total %.1f ms)  mem peak=+%.0f KiB (%.1f MiB resident)\n",
			rm.Name, cpuPer, float64(rm.CPUUsecDelta)/1000.0,
			float64(memDelta)/1024.0, float64(rm.MemPeak)/(1024.0*1024.0))
	}
	if len(resources) == 2 && resources[0].OK && resources[1].OK &&
		resources[0].OKCount > 0 && resources[1].OKCount > 0 {
		pqcPer := float64(resources[0].CPUUsecDelta) / float64(resources[0].OKCount)
		clPer := float64(resources[1].CPUUsecDelta) / float64(resources[1].OKCount)
		if clPer > 0 {
			fmt.Printf("  [Resources] PQC adds %.1f us CPU/handshake vs classical (%.1f vs %.1f, %.1fx)\n",
				pqcPer-clPer, pqcPer, clPer, pqcPer/clPer)
		}
	}
}

func benchmarkAuth(c *apiClient, iterations int) (*Result, *Result) {
	login := &Result{Name: "POST /auth/login"}
	logout := &Result{Name: "POST /auth/logout"}

	for i := 0; i < iterations; i++ {
		start := time.Now()
		err := c.login()
		login.Record(time.Since(start), err)

		start = time.Now()
		err2 := c.logout()
		logout.Record(time.Since(start), err2)
	}
	// Re-login for subsequent tests
	c.login()
	return login, logout
}

func benchmarkSign(c *apiClient, pdfBytes []byte, iterations int) *Result {
	result := &Result{Name: "POST /api/documents/sign (ML-DSA)"}
	for i := 0; i < iterations; i++ {
		_, d, err := c.signPDF(pdfBytes)
		result.Record(d, err)
	}
	return result
}

func benchmarkDownload(c *apiClient, pdfBytes []byte, iterations int) *Result {
	result := &Result{Name: "GET /documents/{id}/download"}

	// Pre-sign one document to use for all download iterations
	id, _, err := c.signPDF(pdfBytes)
	if err != nil {
		log.Printf("  [WARN] Could not pre-sign PDF for download benchmark: %v", err)
		result.Failures = iterations
		return result
	}

	for i := 0; i < iterations; i++ {
		_, d, err := c.downloadPDF(id)
		result.Record(d, err)
	}
	return result
}

func benchmarkVerify(c *apiClient, pdfBytes []byte, iterations int) *Result {
	result := &Result{Name: "POST /api/documents/verify (ML-DSA)"}

	// Step 1: sign once to get a real signature
	var signatureB64 string
	{
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "document.pdf")
		fw.Write(pdfBytes)
		mw.Close()

		resp, err := c.do("POST", "/api/documents/sign", &buf, mw.FormDataContentType())
		if err != nil {
			log.Printf("  [WARN] verify benchmark: could not sign PDF: %v", err)
			result.Failures = iterations
			return result
		}
		defer resp.Body.Close()
		var signResult map[string]any
		json.NewDecoder(resp.Body).Decode(&signResult)
		signatureB64, _ = signResult["signature"].(string)
		if signatureB64 == "" {
			log.Printf("  [WARN] verify benchmark: no signature in sign response: %v", signResult)
			result.Failures = iterations
			return result
		}
	}

	// Step 2: fetch the server public key once
	pubKeyPEM, err := c.getPublicKeyPEM()
	if err != nil {
		log.Printf("  [WARN] verify benchmark: could not get public key: %v", err)
		result.Failures = iterations
		return result
	}

	// Step 3: benchmark verify
	for i := 0; i < iterations; i++ {
		_, d, err := c.verifyPDF(pdfBytes, signatureB64, pubKeyPEM)
		result.Record(d, err)
	}
	return result
}

func benchmarkHealth(c *apiClient, iterations int) *Result {
	result := &Result{Name: "GET /admin/health"}
	for i := 0; i < iterations; i++ {
		start := time.Now()
		resp, err := c.do("GET", "/api/admin/health", nil, "")
		d := time.Since(start)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 200 {
				err = fmt.Errorf("status %d", resp.StatusCode)
			}
		}
		result.Record(d, err)
	}
	return result
}

// ─── Artifact sizes ────────────────────────────────────────────────────────────

// ArtifactSizes captures the on-the-wire sizes of the cryptographic material
// produced by ML-DSA-65 signing. Sizes are reported in raw decoded bytes.
type ArtifactSizes struct {
	SignatureBytes int // raw ML-DSA-65 signature length (fixed for the scheme)
	PublicKeyBytes int // raw DER length of the public key (decoded from PEM)
	PublicKeyPEM   int // PEM-encoded public key length (as served by the API)
}

// measureArtifactSizes signs the PDF once and inspects the returned signature
// and the server public key to report their sizes. Returns an error if either
// artifact cannot be obtained.
func measureArtifactSizes(c *apiClient, pdfBytes []byte) (ArtifactSizes, error) {
	var sizes ArtifactSizes

	// Sign once to obtain a real signature.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "document.pdf")
	fw.Write(pdfBytes)
	mw.Close()

	resp, err := c.do("POST", "/api/documents/sign", &buf, mw.FormDataContentType())
	if err != nil {
		return sizes, fmt.Errorf("sign request failed: %w", err)
	}
	defer resp.Body.Close()

	var signResult map[string]any
	json.NewDecoder(resp.Body).Decode(&signResult)
	sigB64, _ := signResult["signature"].(string)
	if sigB64 == "" {
		return sizes, fmt.Errorf("no signature in sign response: %v", signResult)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return sizes, fmt.Errorf("cannot decode signature base64: %w", err)
	}
	sizes.SignatureBytes = len(sigBytes)

	// Fetch the public key and measure both its PEM and raw DER size.
	pubKeyPEM, err := c.getPublicKeyPEM()
	if err != nil {
		return sizes, fmt.Errorf("cannot fetch public key: %w", err)
	}
	sizes.PublicKeyPEM = len(pubKeyPEM)
	if block, _ := pem.Decode([]byte(pubKeyPEM)); block != nil {
		sizes.PublicKeyBytes = len(block.Bytes)
	}

	return sizes, nil
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  PQC API Test Harness")
	fmt.Printf("  Target : %s\n", *baseURL)
	fmt.Printf("  CA cert : %s\n", *caPath)
	fmt.Printf("  PDF     : %s\n", *pdfPath)
	fmt.Printf("  N       : %d iterations per benchmark\n", *n)
	fmt.Printf("  Conc.   : %d concurrent handshake workers\n", *concurrency)
	if *interleave {
		fmt.Printf("  Handshake: interleaved, block=%d\n", *block)
	} else {
		fmt.Printf("  Handshake: sequential per-variant\n")
	}
	fmt.Printf("  Container: %s (CPU/mem sampled via cgroup)\n", *container)
	fmt.Printf("  Go TLS  : X25519MLKEM768 enabled by default (Go 1.24+)\n")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// ── Load test PDF ──────────────────────────────────────────────────────
	pdfBytes, err := os.ReadFile(*pdfPath)
	if err != nil {
		log.Fatalf("Cannot read PDF %q: %v\n"+
			"  Create a dummy PDF: echo '%%PDF-1.4' > sample.pdf", *pdfPath, err)
	}
	fmt.Printf("\n  PDF size: %d bytes\n", len(pdfBytes))

	// ── Build HTTP client ──────────────────────────────────────────────────
	client := &apiClient{
		http: buildClient(*caPath),
		base: *baseURL,
	}

	// ── Register & Login ───────────────────────────────────────────────────
	fmt.Println("\n[1/7] Setup: register + login")
	if err := client.register(); err != nil {
		log.Printf("  register: %v (may already exist — continuing)", err)
	}
	if err := client.login(); err != nil {
		log.Fatalf("  login failed: %v", err)
	}
	fmt.Printf("  Logged in as %q  token: %s…\n", *username, client.token[:min(16, len(client.token))])

	// ── Results collection ────────────────────────────────────────────────
	var results []*Result

	// ── Benchmark 1: TLS Handshake ────────────────────────────────────────
	fmt.Printf("\n[2/7] Benchmarking TLS handshake — PQC vs classical (%d iterations)…\n", *n)
	addr := strings.TrimPrefix(*baseURL, "https://")
	var hsResults []*Result
	var hsResources []*ResourceMetrics
	if *interleave {
		hsResults, hsResources = benchmarkHandshakeInterleaved(addr, *caPath, *container, *n, *concurrency, *block)
	} else {
		hsResults, hsResources = benchmarkHandshake(addr, *caPath, *container, *n, *concurrency)
	}
	results = append(results, hsResults...)

	// ── Benchmark 2: Auth endpoints ───────────────────────────────────────
	fmt.Printf("\n[3/7] Benchmarking auth endpoints (%d iterations)…\n", *n)
	loginResult, logoutResult := benchmarkAuth(client, *n)
	results = append(results, loginResult, logoutResult)

	// ── Benchmark 3: ML-DSA PDF signing ──────────────────────────────────
	fmt.Printf("\n[4/7] Benchmarking ML-DSA PDF signing (%d iterations)…\n", *n)
	results = append(results, benchmarkSign(client, pdfBytes, *n))

	// ── Benchmark 4: ML-DSA signature verification ───────────────────────
	fmt.Printf("\n[5/7] Benchmarking ML-DSA signature verification (%d iterations)…\n", *n)
	results = append(results, benchmarkVerify(client, pdfBytes, *n))

	// ── Benchmark 5: Signed PDF download ─────────────────────────────────
	fmt.Printf("\n[6/7] Benchmarking signed PDF download (%d iterations)…\n", *n)
	results = append(results, benchmarkDownload(client, pdfBytes, *n))

	// ── Benchmark 6: Admin health ─────────────────────────────────────────
	fmt.Printf("\n[7/7] Benchmarking admin health endpoint (%d iterations)…\n", *n)
	results = append(results, benchmarkHealth(client, *n))

	// ── Measure ML-DSA artifact sizes ────────────────────────────────────
	sizes, err := measureArtifactSizes(client, pdfBytes)
	if err != nil {
		log.Printf("  [WARN] Could not measure artifact sizes: %v", err)
	}

	// ── Print results ──────────────────────────────────────────────────────
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  RESULTS — timing")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	for _, r := range results {
		r.Print()
	}
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  RESULTS — ML-DSA-65 artifact sizes")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  %-40s  %d bytes\n", "Signature size", sizes.SignatureBytes)
	fmt.Printf("  %-40s  %d bytes (DER)\n", "Public key size", sizes.PublicKeyBytes)
	fmt.Printf("  %-40s  %d bytes\n", "Public key size (PEM)", sizes.PublicKeyPEM)
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// ── Export CSV ──────────────────────────────────────────────────────────
	stamp := time.Now().Format("20060102_150405")
	csvPath := "results_" + stamp + ".csv"
	exportCSV(csvPath, results)
	fmt.Printf("\n  CSV exported → %s\n", csvPath)

	sizesPath := "sizes_" + stamp + ".csv"
	exportSizesCSV(sizesPath, sizes, results)
	fmt.Printf("  Sizes CSV exported → %s\n", sizesPath)

	resPath := "resources_" + stamp + ".csv"
	exportResourcesCSV(resPath, hsResources)
	fmt.Printf("  Resources CSV exported → %s\n", resPath)
}

// exportResourcesCSV writes the per-variant server CPU/memory measurements so
// the post-quantum vs classical TLS resource cost can be analysed offline.
func exportResourcesCSV(path string, resources []*ResourceMetrics) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Cannot create resources CSV: %v", err)
		return
	}
	defer f.Close()

	fmt.Fprintln(f, "variant,iterations,concurrency,ok_handshakes,cpu_usec_total,cpu_usec_per_handshake,mem_before_bytes,mem_peak_bytes,mem_delta_bytes,cgroup_ok")
	for _, rm := range resources {
		label := strings.ReplaceAll(rm.Name, ",", ";")
		var cpuPer float64
		if rm.OKCount > 0 {
			cpuPer = float64(rm.CPUUsecDelta) / float64(rm.OKCount)
		}
		fmt.Fprintf(f, "%s,%d,%d,%d,%d,%.2f,%d,%d,%d,%t\n",
			label, rm.Iterations, rm.Concurrency, rm.OKCount,
			rm.CPUUsecDelta, cpuPer, rm.MemBefore, rm.MemPeak,
			rm.MemPeak-rm.MemBefore, rm.OK)
	}
}

// exportSizesCSV writes the ML-DSA-65 artifact sizes and the measured TLS
// handshake sizes to a CSV.
func exportSizesCSV(path string, sizes ArtifactSizes, results []*Result) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Cannot create sizes CSV: %v", err)
		return
	}
	defer f.Close()

	fmt.Fprintln(f, "artifact,bytes")
	fmt.Fprintf(f, "signature,%d\n", sizes.SignatureBytes)
	fmt.Fprintf(f, "public_key_der,%d\n", sizes.PublicKeyBytes)
	fmt.Fprintf(f, "public_key_pem,%d\n", sizes.PublicKeyPEM)

	for _, r := range results {
		if r.HandshakeBytesSent == 0 && r.HandshakeBytesRecv == 0 {
			continue
		}
		label := strings.ReplaceAll(r.Name, ",", ";")
		fmt.Fprintf(f, "%s (sent),%d\n", label, r.HandshakeBytesSent)
		fmt.Fprintf(f, "%s (recv),%d\n", label, r.HandshakeBytesRecv)
		fmt.Fprintf(f, "%s (total),%d\n", label, r.HandshakeBytesSent+r.HandshakeBytesRecv)
	}
}

// exportCSV writes every raw sample to a CSV for further analysis in Python/R.
func exportCSV(path string, results []*Result) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Cannot create CSV: %v", err)
		return
	}
	defer f.Close()

	fmt.Fprintln(f, "benchmark,iteration,duration_us")
	for _, r := range results {
		name := strings.ReplaceAll(r.Name, ",", ";")
		for i, d := range r.Samples {
			fmt.Fprintf(f, "%s,%d,%d\n", name, i+1, d.Microseconds())
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Verify X25519MLKEM768 constant exists at compile time ────────────────────
// This fails to compile on Go < 1.24, giving a clear error message.
var _ tls.CurveID = tls.X25519MLKEM768

// Helper: extract the PDF base name without extension for report labelling.
func pdfBaseName(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}
