package ingress

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestBandwidthChargingWriter_StopsAtLimit(t *testing.T) {
	remaining := int64(10)
	consume := func(bytes int64) (bool, error) {
		if bytes <= 0 {
			return true, nil
		}
		if remaining < bytes {
			return false, nil
		}
		remaining -= bytes
		return true, nil
	}

	var dst bytes.Buffer
	cw := &bandwidthChargingWriter{w: &dst, consume: consume}

	n, err := cw.Write(bytes.Repeat([]byte{'a'}, 5))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes written, got %d", n)
	}

	n, err = cw.Write(bytes.Repeat([]byte{'b'}, 6))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes written on limit, got %d", n)
	}
	if dst.Len() != 5 {
		t.Fatalf("expected dst len 5, got %d", dst.Len())
	}
}

func TestCopyBidirectionalWithReaderCharging_ClosesOnLimit(t *testing.T) {
	clientA, clientB := net.Pipe()
	streamA, streamB := net.Pipe()
	defer func() {
		_ = clientA.Close()
		_ = clientB.Close()
		_ = streamA.Close()
		_ = streamB.Close()
	}()

	_ = clientA.SetDeadline(time.Now().Add(2 * time.Second))
	_ = clientB.SetDeadline(time.Now().Add(2 * time.Second))
	_ = streamA.SetDeadline(time.Now().Add(2 * time.Second))
	_ = streamB.SetDeadline(time.Now().Add(2 * time.Second))

	remaining := int64(10)
	consume := func(bytes int64) (bool, error) {
		if bytes <= 0 {
			return true, nil
		}
		if remaining < bytes {
			return false, nil
		}
		remaining -= bytes
		return true, nil
	}

	done := make(chan int64, 1)
	go func() {
		reader := bufio.NewReader(streamA)
		done <- copyBidirectionalWithReaderCharging(clientA, streamA, reader, consume)
	}()

	// Send first chunk and ensure it's delivered.
	_, _ = streamB.Write(bytes.Repeat([]byte{'x'}, 8))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(clientB, buf); err != nil {
		t.Fatalf("expected to receive first 8 bytes, got error: %v", err)
	}

	// Second chunk should be blocked by limit and close the connection.
	_, _ = streamB.Write(bytes.Repeat([]byte{'y'}, 8))
	_ = clientB.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	readMore := make([]byte, 16)
	n, err := clientB.Read(readMore)
	if n != 0 {
		t.Fatalf("expected 0 bytes after limit, got %d", n)
	}
	if err == nil {
		t.Fatalf("expected error/EOF after limit, got nil")
	}

	select {
	case total := <-done:
		if total != 8 {
			t.Fatalf("expected copy total 8, got %d", total)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for copy to finish")
	}
}
