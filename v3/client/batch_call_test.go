package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBatchCallContextSuccess(t *testing.T) {
	originExecutor := batchCallExecutor
	t.Cleanup(func() {
		batchCallExecutor = originExecutor
	})
	batchCallExecutor = func(_ *Connection, _ context.Context, result interface{}, method string, _ ...interface{}) error {
		switch method {
		case "getBlockNumber":
			*(result.(*int64)) = 100
		case "getPeers":
			*(result.(*[]string)) = []string{"node0", "node1"}
		case "getGroupList":
			*(result.(*[]string)) = []string{"group0"}
		}
		return nil
	}
	conn := &Connection{}

	var blockNumber int64
	var peers []string
	var groups []string
	elems := []BatchElem{
		{Method: "getBlockNumber", Result: &blockNumber},
		{Method: "getPeers", Result: &peers},
		{Method: "getGroupList", Result: &groups},
	}

	if err := conn.BatchCallContext(context.Background(), elems); err != nil {
		t.Fatalf("batch call failed: %v", err)
	}
	for i, elem := range elems {
		if elem.Error != nil {
			t.Fatalf("element %d should not fail: %v", i, elem.Error)
		}
	}
	if blockNumber != 100 {
		t.Fatalf("unexpected block number: %d", blockNumber)
	}
	if len(peers) != 2 || peers[0] != "node0" {
		t.Fatalf("unexpected peers: %#v", peers)
	}
	if len(groups) != 1 || groups[0] != "group0" {
		t.Fatalf("unexpected groups: %#v", groups)
	}
}

func TestBatchCallContextPartialFailureIsolation(t *testing.T) {
	expectedErr := errors.New("mock failure")
	originExecutor := batchCallExecutor
	t.Cleanup(func() {
		batchCallExecutor = originExecutor
	})
	batchCallExecutor = func(_ *Connection, _ context.Context, result interface{}, method string, _ ...interface{}) error {
		switch method {
		case "getBlockNumber":
			*(result.(*int64)) = 123
			return nil
		case "getPeers":
			return expectedErr
		default:
			*(result.(*[]string)) = []string{"group0", "group1"}
			return nil
		}
	}
	conn := &Connection{}

	var blockNumber int64
	var peers []string
	var groups []string
	elems := []BatchElem{
		{Method: "getBlockNumber", Result: &blockNumber},
		{Method: "getPeers", Result: &peers},
		{Method: "getGroupList", Result: &groups},
	}

	if err := conn.BatchCallContext(context.Background(), elems); err != nil {
		t.Fatalf("batch call returned unexpected error: %v", err)
	}
	if elems[0].Error != nil {
		t.Fatalf("unexpected element error: %v", elems[0].Error)
	}
	if !errors.Is(elems[1].Error, expectedErr) {
		t.Fatalf("expected isolated error, got: %v", elems[1].Error)
	}
	if elems[2].Error != nil {
		t.Fatalf("unexpected element error: %v", elems[2].Error)
	}
}

func TestBatchCallContextCancelTimeout(t *testing.T) {
	originExecutor := batchCallExecutor
	t.Cleanup(func() {
		batchCallExecutor = originExecutor
	})
	batchCallExecutor = func(_ *Connection, ctx context.Context, result interface{}, method string, _ ...interface{}) error {
		switch method {
		case "fast":
			*(result.(*int64)) = 7
			return nil
		default:
			<-ctx.Done()
			return ctx.Err()
		}
	}
	conn := &Connection{}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	var fast int64
	var slow int64
	elems := []BatchElem{
		{Method: "fast", Result: &fast},
		{Method: "slow", Result: &slow},
	}

	err := conn.BatchCallContext(ctx, elems)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got: %v", err)
	}
	if elems[0].Error != nil {
		t.Fatalf("fast element should succeed, got: %v", elems[0].Error)
	}
	if !errors.Is(elems[1].Error, context.DeadlineExceeded) {
		t.Fatalf("slow element should be canceled, got: %v", elems[1].Error)
	}
}

func TestBatchCallContextRejectsStateChangingMethods(t *testing.T) {
	originExecutor := batchCallExecutor
	t.Cleanup(func() {
		batchCallExecutor = originExecutor
	})
	batchCallExecutor = func(_ *Connection, _ context.Context, _ interface{}, _ string, _ ...interface{}) error {
		return nil
	}
	conn := &Connection{}

	elems := []BatchElem{
		{Method: "sendTransaction"},
		{Method: "getBlockNumber"},
	}
	if err := conn.BatchCallContext(context.Background(), elems); err != nil {
		t.Fatalf("batch call returned unexpected error: %v", err)
	}
	if elems[0].Error == nil || !strings.Contains(elems[0].Error.Error(), "cannot be used in batch call") {
		t.Fatalf("expected batch method rejection error, got: %v", elems[0].Error)
	}
	if elems[1].Error != nil {
		t.Fatalf("read-only method should still execute: %v", elems[1].Error)
	}
}

func BenchmarkBatchCallContextVsSerial(b *testing.B) {
	originExecutor := batchCallExecutor
	b.Cleanup(func() {
		batchCallExecutor = originExecutor
	})
	batchCallExecutor = func(_ *Connection, _ context.Context, result interface{}, _ string, _ ...interface{}) error {
		time.Sleep(100 * time.Microsecond)
		*(result.(*int64)) = 1
		return nil
	}
	conn := &Connection{}

	makeElems := func() []BatchElem {
		results := make([]int64, 8)
		elems := make([]BatchElem, len(results))
		for i := range results {
			elems[i] = BatchElem{Method: "getBlockNumber", Result: &results[i]}
		}
		return elems
	}

	b.Run("serial", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			elems := makeElems()
			for j := range elems {
				if err := batchCallExecutor(conn, context.Background(), elems[j].Result, elems[j].Method, elems[j].Args...); err != nil {
					b.Fatalf("serial call failed: %v", err)
				}
			}
		}
	})

	b.Run("batch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			elems := makeElems()
			if err := conn.BatchCallContext(context.Background(), elems); err != nil {
				b.Fatalf("batch call failed: %v", err)
			}
		}
	})
}
