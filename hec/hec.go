// (c) Gareth Watts 2017
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the name of the <organization> nor the
//       names of its contributors may be used to endorse or promote products
//       derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/*
Package hec provides a client for Splunk's HTTP Event Collector.

The Client supports opening multiple EventWriters which can be used
as a simple io.Writer for sending complete events to Splunk.  This makes
it easy to drop in as a write target for most log packages.

For example, to route Go's standard logger to a Splunk instance,
configure a new token on the Splunk instance and configure a client:

	server := "https://splunk.example.com/services/collector"
	token := "1111-2222-3333-4444"
	client := hec.New(server, token)

	ew := client.NewEventWriter("", "myprogram", "golog", "hostname", "main")
	log.SetOutput(w)

	log.Println("This log example will be sent to Splunk")

	// must call Close before exiting the program to ensure buffered
	// data is flushed through to Splunk.
	client.Close(time.Minute)

Individual events can also be transmitted directly using the client.WriteEvent
method.
*/
package hec

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
)

var (
	// DefaultFlushInterval specifies how often the buffer will be flushed
	// to the Splunk server if DefaultBufferSize bytes of data have not
	// been accumulated first.
	DefaultFlushInterval = 5 * time.Second

	// DefaultBufferSize specifies the maximum amount of raw (uncompressed)
	// data the client will store before triggering a flush to the Splunk
	// server ahead of DefaultFlushInterval being reached.
	DefaultBufferSize = 128 * 1024

	// DefaultQueueDepth specifies the number of events that the writer will
	// buffer before either blocking, or dropping them depending on configuration.
	DefaultQueueDepth = 10000

	// DefaultRequestTimeout sets the maximum amount of time an individual
	// data transmission request to Splunk should take before its canceled
	// and retried.
	DefaultRequestTimeout = 30 * time.Second
)

// Errors returned by the client.
var (
	ErrQueueFull = errors.New("log queue is full")
	ErrTimeout   = errors.New("timeout waiting for flush")
)

// Event defines a single event to send to Splunk, along  with optional
// metadata.
type Event struct {
	// Data holds the event payload to be indexed.  This can be a text
	// string (possibly including newlines), or a JSON marshalable structure.
	Data interface{} `json:"event"`

	// Timestamp for the event; defaults to the current time.  Supports
	// millisecond accuracy.
	Time time.Time `json:"-"`

	// Host metadata field; overrides the value set on the Splunk input.
	Host string `json:"host,omitempty"`

	// Source metadata field; overrides the value set on the Splunk input.
	Source string `json:"source,omitempty"`

	// Sourcetype metadata field; overrides the default value set on the Splunk input.
	SourceType string `json:"sourcetype,omitempty"`

	// Sourcetype metadata field; overrides the default value set on the Splunk input.
	Index string `json:"index,omitempty"`
}

type encodedEvent struct {
	Event
	EncTime float64 `json:"time,omitempty"`
}

// Config is the argument type expected by New for optional configuration
// parameters.
type Config func(c *Client)

// WithFlushInterval overrides DefaultFlushInterval.
func WithFlushInterval(d time.Duration) Config {
	return func(c *Client) {
		c.flushInterval = d
	}
}

// WithQueueDepth overrides DefaultQueueDepth.
func WithQueueDepth(n int) Config {
	return func(c *Client) {
		c.workQueue = make(chan []byte, n)
	}
}

// WithBufferSize overrides DefaultBufferSize.
func WithBufferSize(n int) Config {
	return func(c *Client) {
		c.bufferSize = n
	}
}

// WithRetryBackOff allows a custom retry policy to be specified.
// By default, an exponential backoff algorithm is used to handle transient
// network or server failures.
func WithRetryBackOff(b backoff.BackOff) Config {
	return func(c *Client) {
		c.backoff = b
	}
}

// WithDropOnFull configures the client to drop incoming log messages
// should the inbound queue fill up (eg. due to the remote server being
// offline, or the message rate being too high).  The default behaviour
// will cause writes to block if the queue is full.
//
// WithQueueDepth can be used to change the amount of data the client will queue.
func WithDropOnFull() Config {
	return func(c *Client) {
		c.dropOnFull = true
	}
}

// WithNoRetry will cause the client to only make a single attempt to flush
// each buffer to the server.  A failure will cause future writes to fail.
//
// By default an exponential retry policy is used instead - See WithRetryBackoff.
func WithNoRetry() Config {
	return WithRetryBackOff(new(backoff.StopBackOff))
}

// WithNoCompression disables the use of gzip compression when sending data
// to the server.
func WithNoCompression() Config {
	return func(c *Client) {
		c.noCompress = true
	}
}

// WithInsecureTransport provides a shortcut to force the client to ignore
// invalid TLS certificates provided by the server.  This can be useful for
// local testing, but should not be used in production.
func WithInsecureTransport() Config {
	return func(c *Client) {
		c.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}
}

// WithHTTPClient specifies an HTTP client for the HEC client to use when
// contacting the Splunk server.  This client should be configured with any
// required root certificates necessary to securely authenticate the remote
// server.
func WithHTTPClient(client *http.Client) Config {
	return func(c *Client) {
		c.client = client
	}
}

// WithRequestTimeout sets a limit for the maximum amount of time a request
// can take to flush data to Splunk.   If the timeout is reached, the request
// will be retried.  This should not be too low, so that only genuinely stuck
// requests are retried.
func WithRequestTimeout(timeout time.Duration) Config {
	return func(c *Client) {
		c.requestTimeout = timeout
	}
}

// WithErrLog defines a logger that should receive messages about problems
// this client has sending data to Splunk.  Defaults to stderr.  Set to nil
// to suppress all notices.
func WithErrLog(log *log.Logger) Config {
	return func(c *Client) {
		c.errLog = log
	}
}

// Client implements an HTTP Event Collector client.
type Client struct {
	client         *http.Client
	requestTimeout time.Duration
	url            string
	token          string
	flushInterval  time.Duration
	bufferSize     int
	workQueue      chan []byte
	err            chan error
	errLog         *log.Logger
	m              sync.RWMutex
	isClosed       bool
	backoff        backoff.BackOff
	cancel         context.CancelFunc
	dropOnFull     bool
	noCompress     bool
	// used by unit tests to control time
	timeAfter func(d time.Duration) <-chan time.Time
}

// New creates a new HTTP Event Collector Client.
//
// url must specify the complete url of the collector endpoint to send to
// eg. https://splunk.example.com:9081/services/collector
//
// token must contain the HEC token configured on the server.
//
// A background goroutine is started by this function.  Call Close or Abort
// to shut it down cleanly.
//
// Call NewEventWriter to receive an io.Writer compatible target to send
// data to.
func New(url string, token string, config ...Config) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		client:         http.DefaultClient,
		requestTimeout: DefaultRequestTimeout,
		url:            url,
		token:          token,
		flushInterval:  DefaultFlushInterval,
		bufferSize:     DefaultBufferSize,
		workQueue:      make(chan []byte, DefaultQueueDepth),
		err:            make(chan error),
		errLog:         log.New(os.Stderr, "", log.LstdFlags),
		backoff:        backoff.NewExponentialBackOff(),
		cancel:         cancel,
		timeAfter:      time.After,
	}
	for _, cfg := range config {
		cfg(client)
	}
	go client.worker(ctx)
	return client
}

// NewEventWriter returns an EventWriter instance which implements an io.Writer interface.
//
// timeFormat specifies an optional time format prefix string to be added
// to each log entry received.  This can be any string that time.Format accepts.
//
// source, sourceytype, host and index are passed through to the Splunk server
// for every submitted event.
//
// Multiple EventWriters can be opened and used concurrently; they are safe
// to use from concurrent goroutines.
func (c *Client) NewEventWriter(timeFormat, source, sourcetype, host, index string) *EventWriter {
	return &EventWriter{
		hec:        c,
		timeFormat: timeFormat,
		tplEvent: Event{
			Source:     source,
			SourceType: sourcetype,
			Host:       host,
			Index:      index,
		},
	}
}

// Close flushes any remaining data to the server and waits until the specified
// timeout for the flush to complete, else returns ErrTimeout.
//
// Close may safely be called multiple times.
//
// No further writes are permitted once Close has been called.
func (c *Client) Close(timeout time.Duration) error {
	c.m.Lock()
	defer c.m.Unlock()
	if c.isClosed {
		return nil
	}

	c.isClosed = true
	close(c.workQueue)
	select {
	case err := <-c.err:
		return err
	case <-time.After(timeout):
		c.cancel()
		return ErrTimeout
	}
}

// Abort closes the connection to the server as rapidly as possible.  It will
// attempt to flush any outstanding data, but will not make any further retries
// if the first attempt fails.
//
// Abort will return nil if all pending data was flushed successfully,
// else it will return an error.
func (c *Client) Abort() error {
	c.m.Lock()
	defer c.m.Unlock()
	if c.isClosed {
		return nil
	}

	c.isClosed = true
	close(c.workQueue)
	c.cancel()
	return <-c.err
}

// WriteEvent queues a single event for transmission.
// This method is goroutine-safe.
func (c *Client) WriteEvent(event Event) error {
	ev := encodedEvent{
		Event: event,
	}
	if !event.Time.IsZero() {
		ev.EncTime = float64(event.Time.Unix()) + (float64(event.Time.Nanosecond()) / 1e9)
	}
	buf, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %v", err)
	}

	c.m.RLock()
	defer c.m.RUnlock()
	if c.isClosed {
		return io.EOF
	}

	if c.dropOnFull {
		select {
		case c.workQueue <- buf:
		default:
			return ErrQueueFull
		}
	} else {
		c.workQueue <- buf
	}
	return nil
}

// worker is executed in a goroutine, receiving data to aggregate
// and forward to Splunk.
func (c *Client) worker(ctx context.Context) {
	b := newBuffer(c.bufferSize, c.noCompress)

	ticker := c.timeAfter(c.flushInterval)
	flush := func() error {
		if b.RawLen() == 0 {
			return nil // nothing to do
		}

		b.Flush() // ensure any buffered data is flushed through
		if err := c.flush(ctx, b); err != nil {
			c.log("hard failure sending data to Splunk: %v", err)
			// swallow any more data written into the channel until its closed
			for {
				select {
				case event := <-c.workQueue:
					if event == nil {
						return err
					}
				}
			}
		}
		b.Reset()
		return nil
	}

	for {
		select {
		case event := <-c.workQueue:
			if event == nil {
				// shutdown requested
				c.err <- flush()
				return
			}

			b.Write(event)
			if b.Len() >= c.bufferSize {
				if err := flush(); err != nil {
					c.err <- err
					return
				}
			}

		case <-ticker:
			if err := flush(); err != nil {
				c.err <- err
				return
			}
			ticker = c.timeAfter(c.flushInterval)
		}
	}
}

func (c *Client) flush(ctx context.Context, buf *buffer) error {
	return backoff.Retry(
		func() error { return c.send(buf) },
		backoff.WithContext(c.backoff, ctx))
}

func (c *Client) send(buf *buffer) error {
	req, err := http.NewRequest("POST", c.url, buf)
	if err != nil {
		c.log("Failed to create HTTP request: %v", err)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	defer cancel() // ensure context resources are released
	req = req.WithContext(ctx)
	if !c.noCompress {
		req.Header.Set("Content-Encoding", "gzip")
	}

	req.Header.Set("Authorization", "Splunk "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		c.log("HTTP request to Splunk failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	// TODO: determine other circumstances upon which we should not retry
	// eg. invalid remote certificate?

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		err := fmt.Errorf("event send failed status=%q error=%q", resp.Status, string(body))
		c.log("HEC event send failed status=%q error=%q", resp.Status, string(body))
		if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
			// configuration error; retrying won't help.
			err = backoff.Permanent(err)
		}
		return err
	}

	return nil
}

func (c *Client) log(format string, v ...interface{}) {
	if c.errLog != nil {
		c.errLog.Printf("splunk-hec "+format, v...)
	}
}

// EventWriter implements an io.Writer interface for sending events to
// the collector.
//
// Each call to Write will emit a single (possibly multi-line) event.
type EventWriter struct {
	hec        *Client
	timeFormat string
	tplEvent   Event
}

// Write encode a single event.  It will generate a timestamp for the event
// immediately and will optionally add a string time prefix to the log entry
// if the writer is so configured.
func (w *EventWriter) Write(p []byte) (n int, err error) {
	now := time.Now()

	event := w.tplEvent
	event.Time = now
	//event.Time = float64(now.Unix()) + (float64(now.Nanosecond()) / 1e9)

	if w.timeFormat != "" {
		event.Data = now.Format(w.timeFormat) + " " + string(p)
	} else {
		event.Data = string(p)
	}

	err = w.hec.WriteEvent(event)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

type buffer struct {
	*bytes.Buffer
	gz *gzip.Writer
	rl int
}

func newBuffer(size int, noGzip bool) *buffer {
	buf := &buffer{
		Buffer: bytes.NewBuffer(make([]byte, 0, size)),
	}
	if !noGzip {
		buf.gz = gzip.NewWriter(buf.Buffer)
	}
	return buf
}

func (b *buffer) Write(p []byte) (int, error) {
	b.rl += len(p)
	if b.gz != nil {
		return b.gz.Write(p)
	}
	return b.Buffer.Write(p)
}

func (b *buffer) Flush() error {
	if b.gz != nil {
		b.gz.Close()
	}
	return nil
}

func (b *buffer) RawLen() int {
	return b.rl
}

func (b *buffer) Reset() {
	b.Buffer.Reset()
	b.rl = 0
	if b.gz != nil {
		b.gz.Reset(b.Buffer)
	}
	b.Buffer.Reset()
}
