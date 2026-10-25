// Package jev is a small client for TypeSafe's Jev (System One) API: typed Noul, Score
// and Choice questions about one state, in one POST {base}/v1/systemone. TypeSafe
// publishes no Go SDK; the wire shape follows its Python SDK (typesafe_sdk 0.7.2). It
// started as agent-guard's client.
//
// The key comes from the caller; the package never reads the environment and never
// logs. Errors carry statuses only, never the state or the response body: it may echo
// the state.
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// DefaultBaseURL is TypeSafe's API. The SDK lets TYPESAFE_BASE_URL override it; a caller
// that does the same checks the value with CheckBaseURL.
const DefaultBaseURL = "https://api.typesafe.ai"

const (
	// maxResponseBytes bounds a response body; an answer is a few hundred bytes.
	maxResponseBytes = 1 << 20
	// maxRetryAfter bounds the wait the server may ask for before a retry.
	maxRetryAfter = time.Minute
	timeout       = 15 * time.Second
	// A connection that has read no frame for pingAfter gets an HTTP/2 ping, and one that
	// does not answer it within pingTimeout is closed: together shorter than timeout, so a
	// call caught on a dead connection fails in time for its retry.
	pingAfter   = 5 * time.Second
	pingTimeout = 5 * time.Second
)

// httpClient is shared, so calls reuse their connections. Its pings close a dead
// connection, so the next call dials again: the default transport kept reusing one
// after its route broke, and every later call and retry timed out on it.
var httpClient = &http.Client{Timeout: timeout, Transport: newTransport(pingAfter, pingTimeout)}

func newTransport(pingAfter, pingTimeout time.Duration) *http.Transport {
	t := &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}
	if d, ok := http.DefaultTransport.(*http.Transport); ok {
		t = d.Clone()
	}
	t.HTTP2 = &http.HTTP2Config{SendPingTimeout: pingAfter, PingTimeout: pingTimeout}
	return t
}

// CheckBaseURL accepts an https URL, or plain http to a loopback address (a local test
// server): the key and the command never cross a network in clear text.
func CheckBaseURL(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return errors.New("jev: the base URL is not a URL")
	}
	switch host := u.Hostname(); {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && (host == "localhost" || net.ParseIP(host).IsLoopback()):
		return nil
	}
	return errors.New("jev: the base URL must use https (plain http only to a loopback address)")
}

// Client calls Jev. The zero value is not usable: set BaseURL and Key.
type Client struct {
	BaseURL string
	Key     string
	// Retries on 408, 429, 5xx and network errors, with back-off from 0.5 s to 5 s, or
	// the server's retry-after.
	Retries int
}

// Question is a Noul (True and False set), a Score (Levels set, lowest first) or a
// Choice (Choices set: each option's name and when it applies; an empty description
// leaves the name alone). A Choice answers exactly one option, so a question that may
// fit none offers a "none" option of its own. Jev reads the instructions and criteria
// literally.
type Question struct {
	Instructions string
	True, False  string
	Levels       []string
	Choices      map[string]string
}

// Answer is a Noul's probability of true; a Score's expected level with the probability
// of each level; or a Choice's option with the probability of each option.
type Answer struct {
	Noul       *float64           `json:"noul,omitempty"`
	Score      *float64           `json:"score,omitempty"`
	Choice     string             `json:"choice,omitempty"`
	Confidence *float64           `json:"confidence,omitempty"`
	Levels     []float64          `json:"levels,omitempty"`
	Options    map[string]float64 `json:"options,omitempty"`
}

// Reply is one call's answers, the model that gave them and what it reported using.
type Reply struct {
	Model        string
	Answers      map[string]Answer
	InputTokens  *int // nil when the response did not say
	OutputTokens *int
	Attempts     int
	Latency      time.Duration // from the first request to the last answer, retries included
}

// StopError is an answer that every later call would get too: the key is refused or the
// account has no credits (401, 402, 403).
type StopError struct{ Status int }

func (e StopError) Error() string { return fmt.Sprintf("jev: HTTP %d, stopping", e.Status) }

// statusError is a failed call. Only the status is kept: the body may echo the request.
type statusError struct{ Status int }

func (e statusError) Error() string { return fmt.Sprintf("jev: HTTP %d", e.Status) }

type wireQuestion struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
	Criteria     any    `json:"criteria"`
}

type request struct {
	State     any                     `json:"state"`
	Model     string                  `json:"model"`
	Questions map[string]wireQuestion `json:"questions"`
}

type response struct {
	Model string `json:"model"`
	Usage *struct {
		InputTokens  *int `json:"input_tokens"`
		OutputTokens *int `json:"output_tokens"`
	} `json:"usage"`
	Answers map[string]struct {
		Type          string             `json:"type"`
		Noul          *float64           `json:"noul"`
		Score         *float64           `json:"score"`
		Choice        string             `json:"choice"`
		Confidence    *float64           `json:"confidence"`
		Probabilities map[string]float64 `json:"probabilities"`
	} `json:"answers"`
}

// Ask asks every question about state in one call.
func (c *Client) Ask(ctx context.Context, model string, state any, questions map[string]Question) (Reply, error) {
	wq := map[string]wireQuestion{}
	for name, q := range questions {
		switch {
		case len(q.Levels) > 0 && len(q.Choices) > 0:
			return Reply{}, fmt.Errorf("jev: %s has both levels and choices", name)
		case len(q.Choices) == 1:
			return Reply{}, fmt.Errorf("jev: %s has one choice", name)
		case len(q.Choices) > 0:
			criteria := map[string]any{}
			for option, when := range q.Choices {
				if option == "" {
					return Reply{}, fmt.Errorf("jev: %s has a choice without a name", name)
				}
				criteria[option] = nil
				if when != "" {
					criteria[option] = when
				}
			}
			wq[name] = wireQuestion{Type: "choice", Instructions: q.Instructions, Criteria: criteria}
		case len(q.Levels) > 0:
			wq[name] = wireQuestion{Type: "score", Instructions: q.Instructions, Criteria: q.Levels}
		default:
			wq[name] = wireQuestion{Type: "noul", Instructions: q.Instructions, Criteria: map[string]string{"true": q.True, "false": q.False}}
		}
	}
	body, err := json.Marshal(request{State: state, Model: model, Questions: wq})
	if err != nil {
		return Reply{}, err
	}
	wait := 500 * time.Millisecond
	start := time.Now()
	for attempt := 1; ; attempt++ {
		r, retryAfter, err := c.call(ctx, body, questions)
		r.Attempts, r.Latency = attempt, time.Since(start)
		var se statusError
		retry := err != nil && !errors.As(err, new(StopError)) &&
			(!errors.As(err, &se) || se.Status == 408 || se.Status == 429 || se.Status >= 500)
		if !retry || attempt > c.Retries {
			return r, err
		}
		d := wait
		if retryAfter > 0 {
			d = retryAfter
		}
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case <-time.After(d):
		}
		wait = min(2*wait, 5*time.Second)
	}
}

func (c *Client) call(ctx context.Context, body []byte, questions map[string]Question) (Reply, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/v1/systemone", bytes.NewReader(body))
	if err != nil {
		return Reply{}, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Reply{}, 0, ctx.Err()
		}
		return Reply{}, 0, errors.New("jev: request failed")
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 402 || resp.StatusCode == 403:
		return Reply{}, 0, StopError{resp.StatusCode}
	case resp.StatusCode != http.StatusOK:
		return Reply{}, retryAfter(resp.Header), statusError{resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	switch {
	case err != nil:
		return Reply{}, 0, errors.New("jev: unreadable response")
	case len(data) > maxResponseBytes:
		return Reply{}, 0, errors.New("jev: response too large")
	}
	var r response
	if err := json.Unmarshal(data, &r); err != nil {
		return Reply{}, 0, errors.New("jev: unreadable response")
	}
	out := Reply{Model: printable(r.Model), Answers: map[string]Answer{}}
	for name, q := range questions {
		a, ok := r.Answers[name]
		if !ok {
			return Reply{}, 0, fmt.Errorf("jev: no answer to %s", name)
		}
		if len(q.Choices) > 0 {
			// A Choice: one of the options asked, a probability for each of them and no
			// other, and the option chosen among the most likely.
			_, asked := q.Choices[a.Choice]
			valid := a.Type == "choice" && asked && probability(a.Confidence) && len(a.Probabilities) == len(q.Choices)
			options := make(map[string]float64, len(q.Choices))
			for option := range q.Choices {
				p, ok := a.Probabilities[option]
				valid = valid && ok && probability(&p) && p <= a.Probabilities[a.Choice]
				options[option] = p
			}
			if !valid {
				return Reply{}, 0, fmt.Errorf("jev: no valid choice for %s", name)
			}
			out.Answers[name] = Answer{Choice: a.Choice, Confidence: a.Confidence, Options: options}
			continue
		}
		if len(q.Levels) == 0 {
			if a.Type != "noul" || !probability(a.Noul) {
				return Reply{}, 0, fmt.Errorf("jev: no valid noul for %s", name)
			}
			out.Answers[name] = Answer{Noul: a.Noul}
			continue
		}
		// A Score: one probability per level asked, keyed "0" upwards, and the expected
		// level within them.
		levels := make([]float64, len(q.Levels))
		valid := a.Type == "score" && len(a.Probabilities) == len(q.Levels) && probability(a.Confidence) &&
			a.Score != nil && *a.Score >= 0 && *a.Score <= float64(len(q.Levels)-1)
		for i := range levels {
			p, ok := a.Probabilities[strconv.Itoa(i)]
			valid = valid && ok && probability(&p)
			levels[i] = p
		}
		if !valid {
			return Reply{}, 0, fmt.Errorf("jev: no valid score for %s", name)
		}
		out.Answers[name] = Answer{Score: a.Score, Confidence: a.Confidence, Levels: levels}
	}
	if r.Usage != nil {
		out.InputTokens, out.OutputTokens = r.Usage.InputTokens, r.Usage.OutputTokens
	}
	return out, 0, nil
}

func probability(p *float64) bool { return p != nil && !math.IsNaN(*p) && *p >= 0 && *p <= 1 }

// printable drops control characters, so a model name the server returns cannot move
// the cursor or rewrite the terminal when a caller prints it.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// retryAfter reads retry-after-ms or retry-after (seconds or an HTTP date), at most
// maxRetryAfter. 0 means none, or a value that is not a positive finite number.
func retryAfter(h http.Header) time.Duration {
	bound := func(seconds float64) time.Duration {
		switch {
		case math.IsNaN(seconds) || seconds <= 0:
			return 0
		case seconds >= maxRetryAfter.Seconds():
			return maxRetryAfter
		}
		return time.Duration(seconds * float64(time.Second))
	}
	if ms, err := strconv.ParseFloat(h.Get("Retry-After-Ms"), 64); err == nil {
		if d := bound(ms / 1000); d > 0 {
			return d
		}
	}
	v := h.Get("Retry-After")
	if s, err := strconv.ParseFloat(v, 64); err == nil {
		return bound(s)
	}
	if t, err := http.ParseTime(v); err == nil {
		return bound(time.Until(t).Seconds())
	}
	return 0
}
