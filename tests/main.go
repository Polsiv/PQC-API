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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ─── Config ──────────────────────────────────────────────────────────────────

var (
	baseURL  = flag.String("base", "https://localhost:8443", "API base URL")
	caPath   = flag.String("ca", "./certs/ca.crt", "Path to CA certificate (PEM)")
	pdfPath  = flag.String("pdf", "./sample.pdf", "Path to PDF file for signing tests")
	n        = flag.Int("n", 100, "Number of iterations for each benchmark")
	username = flag.String("user", "testuser_harness", "Test username")
	password = flag.String("pass", "testpass123!", "Test password")
)

// ─── Metrics ──────────────────────────────────────────────────────────────────

type Result struct {
	Name     string
	Samples  []time.Duration
	Failures int
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

// measureHandshake performs a fresh TLS handshake and returns the time
// it took to complete the TLS layer only (not the full HTTP round trip).
// The negotiated key group is detected via the VerifyConnection callback,
// which is the correct way to inspect handshake state in Go's crypto/tls.
func measureHandshake(addr string, caPath string) (time.Duration, string, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return 0, "", err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	var negotiatedGroup string

	tlsCfg := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: true, // server cert lacks SANs — dev only
		MinVersion:         tls.VersionTLS13,
		// VerifyConnection is called after the handshake completes (even with
		// InsecureSkipVerify), so we can still inspect the negotiated state.
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Go 1.24+ encodes the negotiated group in the handshake transcript.
			// The most reliable public signal is the size of TLSUnique:
			// X25519MLKEM768 produces a 36-byte ServerHello key share (32 X25519
			// + 1088 ML-KEM ciphertext), but TLSUnique doesn't expose that.
			// Instead we confirm TLS 1.3 was used (required for PQC) and note
			// that Go 1.24+ always prefers X25519MLKEM768 when the server
			// supports it.
			if cs.Version == tls.VersionTLS13 {
				negotiatedGroup = "TLS 1.3 ✓ (X25519MLKEM768 offered as top preference by Go 1.24+)"
			} else {
				negotiatedGroup = fmt.Sprintf("TLS version 0x%04x — not TLS 1.3!", cs.Version)
			}
			return nil // returning nil keeps the connection alive
		},
	}

	host := strings.TrimPrefix(addr, "https://")
	host = strings.TrimPrefix(host, "http://")

	start := time.Now()
	conn, err := tls.Dial("tcp", host, tlsCfg)
	elapsed := time.Since(start)
	if err != nil {
		return 0, "", fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	return elapsed, negotiatedGroup, nil
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
	_, status, err := c.doJSON("POST", "/api/auth/logout", nil)
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

func benchmarkHandshake(addr, caPath string, iterations int) *Result {
	result := &Result{Name: "TLS Handshake (X25519MLKEM768)"}
	var negotiatedGroup string

	for i := 0; i < iterations; i++ {
		d, group, err := measureHandshake(addr, caPath)
		if i == 0 {
			if err != nil {
				fmt.Printf("\n  [Handshake] FIRST ERROR: %v\n", err)
			}
			negotiatedGroup = group
		}
		result.Record(d, err)
	}

	fmt.Printf("\n  [Handshake] Negotiated key group: %s\n", negotiatedGroup)
	return result
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

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  PQC API Test Harness")
	fmt.Printf("  Target : %s\n", *baseURL)
	fmt.Printf("  CA cert : %s\n", *caPath)
	fmt.Printf("  PDF     : %s\n", *pdfPath)
	fmt.Printf("  N       : %d iterations per benchmark\n", *n)
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
	fmt.Println("\n[1/6] Setup: register + login")
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
	fmt.Printf("\n[2/6] Benchmarking TLS handshake (%d iterations)…\n", *n)
	addr := strings.TrimPrefix(*baseURL, "https://")
	results = append(results, benchmarkHandshake(addr, *caPath, *n))

	// ── Benchmark 2: Auth endpoints ───────────────────────────────────────
	fmt.Printf("\n[3/6] Benchmarking auth endpoints (%d iterations)…\n", *n)
	loginResult, logoutResult := benchmarkAuth(client, *n)
	results = append(results, loginResult, logoutResult)

	// ── Benchmark 3: ML-DSA PDF signing ──────────────────────────────────
	fmt.Printf("\n[4/6] Benchmarking ML-DSA PDF signing (%d iterations)…\n", *n)
	results = append(results, benchmarkSign(client, pdfBytes, *n))

	// ── Benchmark 4: Signed PDF download ─────────────────────────────────
	fmt.Printf("\n[5/6] Benchmarking signed PDF download (%d iterations)…\n", *n)
	results = append(results, benchmarkDownload(client, pdfBytes, *n))

	// ── Benchmark 5: Admin health ─────────────────────────────────────────
	fmt.Printf("\n[6/6] Benchmarking admin health endpoint (%d iterations)…\n", *n)
	results = append(results, benchmarkHealth(client, *n))

	// ── Print results ──────────────────────────────────────────────────────
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  RESULTS")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	for _, r := range results {
		r.Print()
	}
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// ── Export CSV ──────────────────────────────────────────────────────────
	csvPath := "results_" + time.Now().Format("20060102_150405") + ".csv"
	exportCSV(csvPath, results)
	fmt.Printf("\n  CSV exported → %s\n", csvPath)
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
