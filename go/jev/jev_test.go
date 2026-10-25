package jev

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fake serves Jev's endpoint with the handler and counts the requests.
func fake(t *testing.T, h func(w http.ResponseWriter, r *http.Request, n int)) (*Client, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h(w, r, int(n.Add(1)))
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL + "/", Key: "test-key"}, &n
}

var questions = map[string]Question{
	"risky": {Instructions: "Is it risky?", True: "it is", False: "it is not"},
	"level": {Instructions: "How bad?", Levels: []string{"fine", "odd", "bad"}},
	"owner": {Instructions: "Which app owns it?", Choices: map[string]string{"editor": "", "browser": "a web browser", "none": "no listed app"}},
}

const goodAnswers = `{
  "model": "jev-1\u001b[2J",
  "usage": {"input_tokens": 120, "output_tokens": 9},
  "answers": {
    "risky": {"type": "noul", "noul": 0.25},
    "level": {"type": "score", "score": 1.5, "confidence": 0.8, "probabilities": {"0": 0.1, "1": 0.3, "2": 0.6}},
    "owner": {"type": "choice", "choice": "none", "confidence": 0.7, "probabilities": {"editor": 0.1, "browser": 0.2, "none": 0.7}}
  }
}`

func TestAskSendsEveryQuestionInOneCall(t *testing.T) {
	var got request
	var raw map[string]map[string]map[string]any
	c, n := fake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/systemone" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Error(err)
		}
		_ = json.Unmarshal(body, &raw)
		_, _ = w.Write([]byte(goodAnswers))
	})
	reply, err := c.Ask(context.Background(), "jev-latest", map[string]string{"name": "x"}, questions)
	if err != nil {
		t.Fatal(err)
	}
	if n.Load() != 1 || got.Model != "jev-latest" || len(got.Questions) != 3 {
		t.Fatalf("%d requests, model %q, %d questions", n.Load(), got.Model, len(got.Questions))
	}
	for name, typ := range map[string]string{"risky": "noul", "level": "score", "owner": "choice"} {
		if got.Questions[name].Type != typ {
			t.Errorf("%s sent as %q", name, got.Questions[name].Type)
		}
	}
	// A choice without a description goes as null, so Jev reads its name alone.
	criteria := raw["questions"]["owner"]["criteria"].(map[string]any)
	if v, ok := criteria["editor"]; !ok || v != nil || criteria["browser"] != "a web browser" {
		t.Errorf("choice criteria %v", criteria)
	}

	if reply.Model != "jev-1[2J" || reply.Attempts != 1 || reply.Latency <= 0 {
		t.Errorf("model %q, %d attempts, latency %v", reply.Model, reply.Attempts, reply.Latency)
	}
	if reply.InputTokens == nil || *reply.InputTokens != 120 || *reply.OutputTokens != 9 {
		t.Errorf("usage %v %v", reply.InputTokens, reply.OutputTokens)
	}
	if a := reply.Answers["risky"]; a.Noul == nil || *a.Noul != 0.25 {
		t.Errorf("risky %+v", a)
	}
	if a := reply.Answers["level"]; *a.Score != 1.5 || *a.Confidence != 0.8 || len(a.Levels) != 3 || a.Levels[2] != 0.6 {
		t.Errorf("level %+v", a)
	}
	if a := reply.Answers["owner"]; a.Choice != "none" || *a.Confidence != 0.7 || a.Options["browser"] != 0.2 || len(a.Options) != 3 {
		t.Errorf("owner %+v", a)
	}
}

func TestUnknownUsageStaysNil(t *testing.T) {
	c, _ := fake(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		_, _ = w.Write([]byte(`{"model": "jev-1", "answers": {"risky": {"type": "noul", "noul": 1}}}`))
	})
	reply, err := c.Ask(context.Background(), "jev-latest", "s", map[string]Question{"risky": questions["risky"]})
	if err != nil || reply.InputTokens != nil || reply.OutputTokens != nil {
		t.Fatalf("%v, usage %v %v", err, reply.InputTokens, reply.OutputTokens)
	}
}

func TestRetriesFollowRetryAfter(t *testing.T) {
	c, n := fake(t, func(w http.ResponseWriter, _ *http.Request, n int) {
		if n < 3 {
			w.Header().Set("Retry-After-Ms", "5")
			w.WriteHeader([]int{503, 429}[n-1])
			return
		}
		_, _ = w.Write([]byte(goodAnswers))
	})
	c.Retries = 2
	reply, err := c.Ask(context.Background(), "jev-latest", "s", questions)
	if err != nil || reply.Attempts != 3 || n.Load() != 3 {
		t.Fatalf("%v, %d attempts, %d requests", err, reply.Attempts, n.Load())
	}
}

func TestRetriesRunOut(t *testing.T) {
	c, n := fake(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Retry-After-Ms", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	c.Retries = 1
	reply, err := c.Ask(context.Background(), "jev-latest", "s", questions)
	if err == nil || err.Error() != "jev: HTTP 429" || reply.Attempts != 2 || n.Load() != 2 {
		t.Fatalf("%v, %d attempts, %d requests", err, reply.Attempts, n.Load())
	}
}

func TestStopAndClientErrorsAreNotRetried(t *testing.T) {
	for status, stop := range map[int]bool{401: true, 402: true, 403: true, 400: false, 422: false} {
		c, n := fake(t, func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(status) })
		c.Retries = 3
		_, err := c.Ask(context.Background(), "jev-latest", "s", questions)
		var se StopError
		if err == nil || errors.As(err, &se) != stop || n.Load() != 1 {
			t.Errorf("HTTP %d: %v, %d requests", status, err, n.Load())
		}
		if stop && se.Status != status {
			t.Errorf("HTTP %d: StopError %d", status, se.Status)
		}
	}
}

func TestErrorsNeverCarryTheBodyOrState(t *testing.T) {
	const secret = "sk-not-a-real-key-0123456789"
	for _, h := range []func(http.ResponseWriter){
		func(w http.ResponseWriter) { w.WriteHeader(500); _, _ = w.Write([]byte(secret)) },
		func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"echo": "` + secret + `"`)) },
		func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"answers": {"risky": {"type": "` + secret + `"}}}`))
		},
	} {
		c, _ := fake(t, func(w http.ResponseWriter, _ *http.Request, _ int) { h(w) })
		_, err := c.Ask(context.Background(), "jev-latest", secret, map[string]Question{"risky": questions["risky"]})
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("error %v", err)
		}
	}
}

func TestInvalidAnswersAreRefused(t *testing.T) {
	for _, c := range []struct{ name, question, answer string }{
		{"missing", "risky", `{}`},
		{"noul out of range", "risky", `{"risky": {"type": "noul", "noul": 1.5}}`},
		{"wrong type", "risky", `{"risky": {"type": "score", "noul": 0.5}}`},
		{"score past levels", "level", `{"level": {"type": "score", "score": 3, "confidence": 1, "probabilities": {"0": 0, "1": 0, "2": 1}}}`},
		{"score level missing", "level", `{"level": {"type": "score", "score": 1, "confidence": 1, "probabilities": {"0": 0.5, "2": 0.5}}}`},
		{"choice not offered", "owner", `{"owner": {"type": "choice", "choice": "terminal", "confidence": 0.9, "probabilities": {"editor": 0.1, "browser": 0.1, "none": 0.8}}}`},
		{"choice option extra", "owner", `{"owner": {"type": "choice", "choice": "none", "confidence": 0.9, "probabilities": {"editor": 0.1, "browser": 0.1, "none": 0.7, "terminal": 0.1}}}`},
		{"choice option gone", "owner", `{"owner": {"type": "choice", "choice": "none", "confidence": 0.9, "probabilities": {"editor": 0.1, "none": 0.9}}}`},
		{"choice not the most likely", "owner", `{"owner": {"type": "choice", "choice": "editor", "confidence": 0.9, "probabilities": {"editor": 0.1, "browser": 0.1, "none": 0.8}}}`},
		{"choice no confidence", "owner", `{"owner": {"type": "choice", "choice": "none", "probabilities": {"editor": 0.1, "browser": 0.1, "none": 0.8}}}`},
	} {
		cl, _ := fake(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
			_, _ = w.Write([]byte(`{"model": "jev-1", "answers": ` + c.answer + `}`))
		})
		if _, err := cl.Ask(context.Background(), "jev-latest", "s", map[string]Question{c.question: questions[c.question]}); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestMalformedQuestionsSendNothing(t *testing.T) {
	for name, q := range map[string]Question{
		"levels and choices": {Levels: []string{"a", "b"}, Choices: map[string]string{"a": "", "b": ""}},
		"one choice":         {Choices: map[string]string{"only": ""}},
		"unnamed choice":     {Choices: map[string]string{"": "nothing applies", "x": ""}},
	} {
		c, n := fake(t, func(http.ResponseWriter, *http.Request, int) {})
		if _, err := c.Ask(context.Background(), "jev-latest", "s", map[string]Question{"q": q}); err == nil || n.Load() != 0 {
			t.Errorf("%s: %v, %d requests", name, err, n.Load())
		}
	}
}

func TestOversizedResponseIsRefused(t *testing.T) {
	c, _ := fake(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		_, _ = w.Write([]byte(strings.Repeat(" ", maxResponseBytes+1)))
	})
	if _, err := c.Ask(context.Background(), "jev-latest", "s", questions); err == nil || err.Error() != "jev: response too large" {
		t.Fatalf("%v", err)
	}
}

func TestCancelEndsARequest(t *testing.T) {
	release := make(chan struct{})
	c, _ := fake(t, func(http.ResponseWriter, *http.Request, int) { <-release })
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Ask(ctx, "jev-latest", "s", questions); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestCancelStopsTheWait(t *testing.T) {
	c, _ := fake(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c.Retries = 1
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	reply, err := c.Ask(ctx, "jev-latest", "s", questions)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second || reply.Attempts != 1 {
		t.Fatalf("%v after %v, %d attempts", err, time.Since(start), reply.Attempts)
	}
}

func TestRetryAfter(t *testing.T) {
	for _, c := range []struct {
		name, header, value string
		want                time.Duration
	}{
		{"seconds", "Retry-After", "2", 2 * time.Second},
		{"milliseconds", "Retry-After-Ms", "250", 250 * time.Millisecond},
		{"huge seconds", "Retry-After", "1e30", maxRetryAfter},
		{"huge milliseconds", "Retry-After-Ms", "1e300", maxRetryAfter},
		{"infinity", "Retry-After", "+Inf", maxRetryAfter},
		{"NaN", "Retry-After", "NaN", 0},
		{"negative", "Retry-After", "-5", 0},
		{"past date", "Retry-After", "Mon, 02 Jan 2006 15:04:05 GMT", 0},
		{"far date", "Retry-After", time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat), maxRetryAfter},
		{"none", "Retry-After", "", 0},
	} {
		h := http.Header{}
		h.Set(c.header, c.value)
		if got := retryAfter(h); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCheckBaseURL(t *testing.T) {
	for base, ok := range map[string]bool{
		DefaultBaseURL:               true,
		"http://127.0.0.1:8080":      true,
		"http://[::1]:8080":          true,
		"http://localhost:9":         true,
		"http://api.typesafe.ai":     false,
		"http://127.0.0.1.nip.io:80": false,
		"ftp://127.0.0.1":            false,
		"api.typesafe.ai":            false,
	} {
		if err := CheckBaseURL(base); (err == nil) != ok {
			t.Errorf("%s: %v, want ok=%v", base, err, ok)
		}
	}
}

// proxy forwards TCP connections to a server. freeze leaves every connection open at
// that moment silent both ways without closing it, as a route that broke mid-run does;
// connections made after it forward again.
type proxy struct {
	ln      net.Listener
	accepts atomic.Int32
	mu      sync.Mutex
	conns   []net.Conn
	dead    []*atomic.Bool
}

func newProxy(t *testing.T, server string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln}
	t.Cleanup(func() {
		ln.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, c := range p.conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.accepts.Add(1)
			s, err := net.Dial("tcp", server)
			if err != nil {
				c.Close()
				continue
			}
			dead := new(atomic.Bool)
			p.mu.Lock()
			p.conns = append(p.conns, c, s)
			p.dead = append(p.dead, dead)
			p.mu.Unlock()
			go forward(s, c, dead)
			go forward(c, s, dead)
		}
	}()
	return p
}

func (p *proxy) freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, d := range p.dead {
		d.Store(true)
	}
}

// forward copies src to dst until src ends; once dead, it reads on and drops what it
// reads, so the sender sees neither an answer nor a close.
func forward(dst, src net.Conn, dead *atomic.Bool) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if !dead.Load() && n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if !dead.Load() {
				dst.Close()
			}
			return
		}
	}
}

func TestADeadConnectionIsDialedAgain(t *testing.T) {
	var proto atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto.Store(int32(r.ProtoMajor))
		_, _ = w.Write([]byte(goodAnswers))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	p := newProxy(t, srv.Listener.Addr().String())

	tr := newTransport(200*time.Millisecond, 500*time.Millisecond)
	tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	saved := httpClient
	httpClient = &http.Client{Timeout: timeout, Transport: tr}
	t.Cleanup(func() {
		tr.CloseIdleConnections()
		httpClient = saved
	})

	c := &Client{BaseURL: "https://" + p.ln.Addr().String(), Key: "test-key", Retries: 1}
	state := map[string]string{"name": "x"}
	if _, err := c.Ask(context.Background(), "jev-latest", state, questions); err != nil {
		t.Fatal(err)
	}
	if proto.Load() != 2 {
		t.Fatalf("served over HTTP/%d, so no HTTP/2 ping runs", proto.Load())
	}
	p.freeze()
	start := time.Now()
	// The ping closes the silent connection: a call sent on it fails then, not at its
	// timeout, and its retry dials again.
	if _, err := c.Ask(context.Background(), "jev-latest", state, questions); err != nil {
		t.Fatalf("after the route broke: %v", err)
	}
	// The next call, even without retries, goes over the new connection.
	c.Retries = 0
	if _, err := c.Ask(context.Background(), "jev-latest", state, questions); err != nil {
		t.Fatalf("the next call: %v", err)
	}
	if took := time.Since(start); took > 5*time.Second || p.accepts.Load() != 2 {
		t.Errorf("took %v over %d connections", took, p.accepts.Load())
	}
}
