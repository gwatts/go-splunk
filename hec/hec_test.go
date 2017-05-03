package hec

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
func testTimeAfter(ch chan time.Time) (restore func(), calls chan time.Duration) {
	org := timeAfter
	restore = func() { timeAfter = org }

	calls = make(chan time.Duration, 10)
	timeAfter = func(d time.Duration) <-chan time.Time {
		calls <- d
		return ch
	}
	return restore, calls
}
*/

func makeTimeAfter() (ch chan time.Time, calls chan time.Duration, cfg Config) {
	calls = make(chan time.Duration, 10)
	ch = make(chan time.Time)
	cfg = func(c *Client) {
		c.timeAfter = func(d time.Duration) <-chan time.Time {
			calls <- d
			return ch
		}
	}
	return ch, calls, cfg
}

func decodePayload(buf []byte) (result []Event, err error) {
	dec := json.NewDecoder(bytes.NewReader(buf))
	for dec.More() {
		var entry Event
		if err := dec.Decode(&entry); err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	return result, nil
}

func TestFlushOnClose(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	/*
		ch := make(chan time.Time)
		restore, _ := testTimeAfter(ch)
		defer restore()
	*/

	//ch, _, timeAfterConfig := makeTimeAfter()

	var url string
	var payload []byte
	var headers http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url = r.URL.String()
		headers = r.Header
		payload, _ = ioutil.ReadAll(r.Body)
	}))
	defer srv.Close()

	c := New(srv.URL, "token", WithNoCompression())
	defer c.Abort()
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	_, err := fmt.Fprintln(w, "event one")
	require.Nil(err, "event one write should succeed")
	_, err = fmt.Fprintln(w, "event two")
	require.Nil(err, "event two write should succeed")

	err = c.Close(time.Second)
	require.Nil(err, "Close should not fail")

	assert.Equal("Splunk token", headers.Get("Authorization"), "token should be set")

	messages, err := decodePayload(payload)
	require.Nil(err, "payload should decode")
	assert.Equal(2, len(messages))
	assert.Equal("hst", messages[0].Host)
	assert.Equal("idx", messages[0].Index)
	assert.Equal("st", messages[0].SourceType)
	assert.Equal("src", messages[0].Source)
	assert.Equal("event one\n", messages[0].Data)
	assert.Equal("event two\n", messages[1].Data)
}

func TestFlushOnTimer(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	ch, timeAfterCalls, timeAfterConfig := makeTimeAfter()

	var url string
	var payload []byte
	wait := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url = r.URL.String()
		payload, _ = ioutil.ReadAll(r.Body)
		wait <- struct{}{}
	}))
	defer srv.Close()

	// Make sure the work channel buffers only one element, so we know a flush timeout
	// will actually have work to do

	c := New(srv.URL, "token", WithQueueDepth(0), WithNoCompression(), timeAfterConfig)
	defer c.Abort()
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	_, err := fmt.Fprintln(w, "event one")
	require.Nil(err, "event one write should succeed")
	_, err = fmt.Fprintln(w, "event two")
	require.Nil(err, "event two write should succeed")

	// force a timeout
	ch <- time.Now()

	// wait for flush
	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	messages, err := decodePayload(payload)
	require.Nil(err, "payload should decode")
	assert.Equal(2, len(messages))

	err = c.Close(time.Second)
	require.Nil(err, "Close should not fail")

	// make sure timer was called twice with the correct duration
	for i := 0; i < 2; i++ {
		select {
		case d := <-timeAfterCalls:
			assert.Equal(DefaultFlushInterval, d, "(%d) should be 30")
		default:
			t.Error("incorrect number of calls to timeAfter")
		}
	}

	// flush should not have been called again with an empty buffer
	select {
	case <-wait:
		fmt.Println("Unexpected payload", string(payload))
		t.Error("flush was called during close on empty buffer")
	default:
	}
}

func TestFlushFailure(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	/*
		ch := make(chan time.Time)
		restore, _ := testTimeAfter(ch)
		defer restore()
	*/
	ch, _, timeAfterConfig := makeTimeAfter()

	var url string
	var payload []byte
	wait := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url = r.URL.String()
		payload, _ = ioutil.ReadAll(r.Body)
		http.Error(w, "test failure", 500)
		wait <- struct{}{}
	}))
	defer srv.Close()

	c := New(srv.URL, "token", WithNoCompression(), WithQueueDepth(0), WithNoRetry(), timeAfterConfig)
	defer c.Abort()
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	_, err := fmt.Fprintln(w, "event one")
	require.Nil(err, "event one write should succeed")

	// force a timeout
	ch <- time.Now()

	// wait for flush
	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// next writes should be swallowed
	for i := 0; i < 10; i++ {
		_, err = fmt.Fprintln(w, i)
		assert.Nil(err, "write %d should not error", i)
	}

	// Close should return the flush error
	err = c.Close(time.Second)
	assert.NotNil(err)

	// Write after close should give EOF
	_, err = fmt.Fprintln(w, "test write")
	assert.Equal(io.EOF, err)
}

// Test that calling abort cancels any request retries in progress
func TestRetryAbort(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	/*
		ch := make(chan time.Time)
		restore, _ := testTimeAfter(ch)
		defer restore()
	*/
	ch, _, timeAfterConfig := makeTimeAfter()

	var url string
	var payload []byte
	wait := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url = r.URL.String()
		payload, _ = ioutil.ReadAll(r.Body)
		http.Error(w, "test failure", 500)
		select {
		case wait <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "token",
		WithNoCompression(),
		WithQueueDepth(0),
		WithRetryBackOff(backoff.NewConstantBackOff(time.Minute)),
		timeAfterConfig)
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	_, err := fmt.Fprintln(w, "event one")
	require.Nil(err, "event one write should succeed")

	// force a timeout
	ch <- time.Now()

	// wait for flush
	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// Close should still complete quickly by cancelling the retry
	done := make(chan error, 1)
	go func() { done <- c.Abort() }()

	select {
	case err := <-done:
		assert.NotNil(err)
	case <-time.After(time.Second):
		t.Error("Abort did not cancel retry")
	}

	// Write after close should give EOF
	_, err = fmt.Fprintln(w, "test write")
	assert.Equal(io.EOF, err)

}

func TestBlockOnQueueFull(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	/*
		ch := make(chan time.Time)
		restore, _ := testTimeAfter(ch)
		defer restore()
	*/
	ch, _, timeAfterConfig := makeTimeAfter()

	wait := make(chan struct{}, 10)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wait <- struct{}{}
		<-release
	}))
	defer srv.Close()

	c := New(srv.URL, "token",
		WithNoCompression(),
		WithQueueDepth(0),
		WithNoRetry(),
		timeAfterConfig)
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	_, err := fmt.Fprintln(w, "event one")
	require.Nil(err, "event one write should succeed")

	// force a timeout
	ch <- time.Now()

	// wait for flush
	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// a flush is in progress, and won't complete until we read from the release chan
	// a write now should block until that release happens
	done := make(chan error)
	go func() {
		_, err := fmt.Fprintln(w, "event two")
		done <- err
	}()

	// wait 50ms to confirm that it's blocked
	select {
	case err := <-done:
		t.Fatal("Unexpected response from send", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-done:
		assert.Nil(err)
	case <-time.After(50 * time.Millisecond):
		t.Error("did not complete")
	}
}

func TestDropOnQueueFull(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	/*
		ch := make(chan time.Time)
		restore, _ := testTimeAfter(ch)
		defer restore()
	*/
	ch, _, timeAfterConfig := makeTimeAfter()

	wait := make(chan struct{}, 10)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wait <- struct{}{}
		<-release
	}))
	defer srv.Close()

	c := New(srv.URL, "token",
		WithNoCompression(),
		WithQueueDepth(1),
		WithDropOnFull(),
		WithNoRetry(),
		timeAfterConfig)
	defer c.Abort()
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	_, err := fmt.Fprintln(w, "event one")
	require.Nil(err, "event one write should succeed")

	// wait for flush
	started := false
	for start := time.Now(); !started && time.Since(start) < time.Second; {
		// force a timeout
		ch <- time.Now()
		select {
		case <-wait:
			started = true
		case <-time.After(50 * time.Millisecond):
		}
	}

	if !started {
		close(release)
		t.Fatal("Failed to start flush")
	}

	// flush has started; we should now be able to add one item to the queue and the
	// next should be droppedk
	push := func(msg string) chan error {
		done := make(chan error)
		go func() {
			_, err := fmt.Fprintln(w, msg)
			done <- err
		}()
		return done
	}

	done := push("event two")
	select {
	case err := <-done:
		assert.Nil(err, "event two should not block or error")
	case <-time.After(time.Second):
		close(release)
		t.Fatal("blocked pushing event two")
	}

	done = push("event three")

	select {
	case err := <-done:
		assert.Equal(ErrQueueFull, err)
	case <-time.After(time.Second):
		t.Error("Timed out waiting for response")
	}

	close(release)
}

func TestCloseTimeout(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	/*
		ch := make(chan time.Time)
		restore, _ := testTimeAfter(ch)
		defer restore()
	*/
	ch, _, timeAfterConfig := makeTimeAfter()

	wait := make(chan struct{}, 10)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wait <- struct{}{}
		<-release
	}))
	defer srv.Close()

	c := New(srv.URL, "token",
		WithNoCompression(),
		WithQueueDepth(0),
		WithNoRetry(),
		timeAfterConfig)
	defer c.Abort()
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	_, err := fmt.Fprintln(w, "event one")
	require.Nil(err, "event one write should succeed")

	// trigger flush
	ch <- time.Now()

	// wait for flush
	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	defer close(release)

	// Request close; should timeout
	done := make(chan error, 1)
	go func() {
		done <- c.Close(100 * time.Millisecond)
	}()

	select {
	case err := <-done:
		assert.Equal(ErrTimeout, err)
	case <-time.After(time.Second):
		t.Error("timeout didn't fire")
	}
}

func TestSizeFlush(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	var payload []byte
	wait := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ = ioutil.ReadAll(r.Body)
		wait <- struct{}{}
	}))
	defer srv.Close()

	// set the buffer size to something larger than 1 encoded json message
	c := New(srv.URL, "token",
		WithNoCompression(),
		WithQueueDepth(0),
		WithBufferSize(120))
	defer c.Abort()
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	_, err := fmt.Fprintln(w, "event one")
	require.Nil(err, "event one write should succeed")
	_, err = fmt.Fprintln(w, "event two")
	require.Nil(err, "event two write should succeed")

	// second write should of triggered a flush to size

	// wait for flush
	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	messages, err := decodePayload(payload)
	require.Nil(err, "payload should decode")
	assert.Equal(2, len(messages))

	err = c.Close(time.Second)
	require.Nil(err, "Close should not fail")

	// flush should not have been called again with an empty buffer
	select {
	case <-wait:
		fmt.Println("Unexpected payload", string(payload))
		t.Error("flush was called during close on empty buffer")
	default:
	}
}

// Retries should only happen on transient failures,
// not 400 errors that indicate we've supplied an invalid auth key, etc
func TestRetryOnTransientFailure(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	wait := make(chan struct{}, 10)
	var cc int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&cc, 1)
		if c <= 2 {
			// return a server error for the first couple of requests, which should trigger a retry
			http.Error(w, "test error", 500)
		} else {
			// send a user error after that, which should cause a hard failure
			http.Error(w, "test error", 400)
		}
		wait <- struct{}{}
	}))
	defer srv.Close()

	c := New(srv.URL, "token", WithQueueDepth(0),
		WithNoCompression(),
		WithBufferSize(5), // immediate flush
		WithRetryBackOff(new(backoff.ZeroBackOff)))
	defer c.Abort()
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	_, err := fmt.Fprintln(w, "event one")
	require.Nil(err, "event one write should succeed")

	err = c.Close(time.Second)
	assert.NotNil(err)
	assert.Equal(3, len(wait))
}

func TestGzipCompression(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	wait := make(chan struct{}, 10)
	var headers http.Header
	var payload []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ = ioutil.ReadAll(r.Body)
		headers = r.Header
		wait <- struct{}{}
	}))

	c := New(srv.URL, "token")
	defer c.Abort()
	w := c.NewEventWriter("", "src", "st", "hst", "idx")

	fmt.Fprintln(w, "event one")
	fmt.Fprintln(w, "event two")
	err := c.Close(time.Second)
	require.Nil(err)

	select {
	case <-wait:
	default:
		t.Fatal("Data was not flushed to HTTP server")
	}

	assert.Equal("gzip", headers.Get("Content-Encoding"), "content encoding should be gzip")

	gz, err := gzip.NewReader(bytes.NewReader(payload))
	require.Nil(err, "create gzip reader")
	data, err := ioutil.ReadAll(gz)
	require.Nil(err, "read from gzip reader")

	messages, err := decodePayload(data)
	require.Nil(err, "decode sent payload")
	assert.Equal(2, len(messages))
	assert.Equal("event one\n", messages[0].Data)
	assert.Equal("event two\n", messages[1].Data)

}
