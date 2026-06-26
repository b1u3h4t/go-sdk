package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/FISCO-BCOS/bcos-c-sdk/bindings/go/csdk"
	"github.com/ethereum/go-ethereum/common"
)

// SignEncodedOpts optional parameters for SignEncodedTransactionWithFullFields.
type SignEncodedOpts struct {
	// Nonce is written into TransactionData when non-empty (custom nonce / anti-replay).
	Nonce string
	// ExtraData is passed to the C SDK extra_data field.
	ExtraData string
	// PrivateKey when set (32 bytes) signs with an ephemeral keypair instead of the client's default key.
	PrivateKey []byte
	// Attribute is the transaction attribute flag (usually 0).
	Attribute int32
}

// SignedEncodedTx holds the chain tx hash and signed encoded bytes for SendEncodedTransaction.
type SignedEncodedTx struct {
	TxHash  string
	Encoded []byte
}

// SignEncodedTransactionWithFullFields builds and signs a V1 transaction in one C SDK call
// (bcos_sdk_create_signed_transaction_with_full_fields), matching rust-gears-sdk full_fields path.
func (c *Client) SignEncodedTransactionWithFullFields(
	ctx context.Context,
	to *common.Address,
	input []byte,
	abi string,
	opts *SignEncodedOpts,
) (*SignedEncodedTx, error) {
	_ = ctx
	if c == nil {
		return nil, fmt.Errorf("client is nil")
	}
	blockLimit, err := c.blockLimitForTransaction()
	if err != nil {
		return nil, fmt.Errorf("get block limit: %w", err)
	}
	toHex := ""
	if to != nil {
		toHex = strings.ToLower(to.String()[2:])
	}
	nonce, extra, attr := "", "", int32(0)
	var privateKey []byte
	if opts != nil {
		nonce = strings.TrimSpace(opts.Nonce)
		extra = opts.ExtraData
		attr = opts.Attribute
		if len(opts.PrivateKey) == 32 {
			privateKey = opts.PrivateKey
		}
	}
	csdkConn := c.conn.GetCSDK()
	var pair *csdk.SignedTxPair
	if len(privateKey) == 32 {
		pair, err = csdkConn.CreateSignedTransactionWithPrivateKey(
			privateKey, blockLimit, toHex, nonce, input, abi, attr, extra,
		)
	} else {
		pair, err = csdkConn.CreateSignedTransactionWithDefaultKeyPair(
			blockLimit, toHex, nonce, input, abi, attr, extra,
		)
	}
	if err != nil {
		return nil, err
	}
	return &SignedEncodedTx{
		TxHash:  pair.TxHash,
		Encoded: pair.SignedTx,
	}, nil
}
