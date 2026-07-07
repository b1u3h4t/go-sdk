package client

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/FISCO-BCOS/bcos-c-sdk/bindings/go/csdk"
)

// Endpoint is a BCOS RPC peer address.
type Endpoint struct {
	Host string
	Port int
}

// SdkCommonConfig maps to INI [common] when connecting programmatically with multiple peers.
// Zero values use INI defaults (thread_pool_size=8, message_timeout_ms=10000,
// send_rpc_request_to_highest_block_node=true).
type SdkCommonConfig struct {
	ThreadPoolSize                   int
	MessageTimeoutMs                 int
	SendRpcRequestToHighestBlockNode bool
	ThreadPoolSizeSet                bool
	MessageTimeoutMsSet              bool
	SendToHighestBlockNodeSet        bool
}

// ParseEndpoint parses "host:port" (supports IPv6 bracket form from net.SplitHostPort).
func ParseEndpoint(raw string) (Endpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Endpoint{}, fmt.Errorf("empty endpoint")
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid endpoint %q: %w", raw, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return Endpoint{}, fmt.Errorf("invalid endpoint port in %q", raw)
	}
	return Endpoint{Host: host, Port: port}, nil
}

// ParseEndpoints parses a list of "host:port" strings.
func ParseEndpoints(raw []string) ([]Endpoint, error) {
	out := make([]Endpoint, 0, len(raw))
	for _, item := range raw {
		ep, err := ParseEndpoint(item)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, nil
}

// EffectivePeers returns explicit Peers, or a single entry from Host/Port when Peers is empty.
func (c *Config) EffectivePeers() []Endpoint {
	if len(c.Peers) > 0 {
		return append([]Endpoint(nil), c.Peers...)
	}
	if c.Host != "" && c.Port > 0 {
		return []Endpoint{{Host: c.Host, Port: c.Port}}
	}
	return nil
}

func (c *Config) csdkOptions() *csdk.SdkOptions {
	if !c.SdkCommon.ThreadPoolSizeSet &&
		!c.SdkCommon.MessageTimeoutMsSet &&
		!c.SdkCommon.SendToHighestBlockNodeSet {
		return nil
	}
	opts := &csdk.SdkOptions{}
	if c.SdkCommon.ThreadPoolSizeSet {
		v := c.SdkCommon.ThreadPoolSize
		opts.ThreadPoolSize = &v
	}
	if c.SdkCommon.MessageTimeoutMsSet {
		v := c.SdkCommon.MessageTimeoutMs
		opts.MessageTimeoutMs = &v
	}
	if c.SdkCommon.SendToHighestBlockNodeSet {
		v := c.SdkCommon.SendRpcRequestToHighestBlockNode
		opts.SendRpcRequestToHighestBlockNode = &v
	}
	return opts
}

func toCSDKEndpoints(peers []Endpoint) []csdk.Endpoint {
	out := make([]csdk.Endpoint, len(peers))
	for i, p := range peers {
		out[i] = csdk.Endpoint{Host: p.Host, Port: p.Port}
	}
	return out
}
