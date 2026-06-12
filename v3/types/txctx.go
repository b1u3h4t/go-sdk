package types

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
)

type beforeSendTxHashKey struct{}

// ContextWithBeforeSendTxHash attaches a callback invoked after the signed tx hash
// is known and before the transaction is broadcast to the node.
func ContextWithBeforeSendTxHash(ctx context.Context, fn func(common.Hash)) context.Context {
	if fn == nil {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, beforeSendTxHashKey{}, fn)
}

// BeforeSendTxHashFromContext returns the callback attached by ContextWithBeforeSendTxHash.
func BeforeSendTxHashFromContext(ctx context.Context) func(common.Hash) {
	if ctx == nil {
		return nil
	}
	fn, _ := ctx.Value(beforeSendTxHashKey{}).(func(common.Hash))
	return fn
}
