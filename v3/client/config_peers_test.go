package client

import (
	"testing"
)

func TestParseEndpoint(t *testing.T) {
	ep, err := ParseEndpoint("192.168.9.134:20201")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "192.168.9.134" || ep.Port != 20201 {
		t.Fatalf("unexpected endpoint: %+v", ep)
	}

	ep, err = ParseEndpoint("[::1]:20200")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "::1" || ep.Port != 20200 {
		t.Fatalf("unexpected ipv6 endpoint: %+v", ep)
	}

	if _, err = ParseEndpoint("bad"); err == nil {
		t.Fatal("expected error for bad endpoint")
	}
}

func TestEffectivePeers(t *testing.T) {
	cfg := &Config{Host: "127.0.0.1", Port: 20200}
	peers := cfg.EffectivePeers()
	if len(peers) != 1 || peers[0].Host != "127.0.0.1" || peers[0].Port != 20200 {
		t.Fatalf("unexpected peers: %+v", peers)
	}

	cfg.Peers = []Endpoint{{Host: "10.0.0.1", Port: 20201}, {Host: "10.0.0.2", Port: 20202}}
	peers = cfg.EffectivePeers()
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %+v", peers)
	}
}

func TestConfigCSDKOptions(t *testing.T) {
	if cfg := (&Config{}).csdkOptions(); cfg != nil {
		t.Fatal("expected nil options when SdkCommon unset")
	}

	cfg := &Config{
		SdkCommon: SdkCommonConfig{
			ThreadPoolSize:    16,
			ThreadPoolSizeSet: true,
		},
	}
	opts := cfg.csdkOptions()
	if opts == nil || opts.ThreadPoolSize == nil || *opts.ThreadPoolSize != 16 {
		t.Fatalf("unexpected opts: %+v", opts)
	}
}

func TestNewConnectionRoutingValidation(t *testing.T) {
	if _, err := NewConnection(nil); err == nil {
		t.Fatal("expected error for nil config")
	}
	if _, err := NewConnection(&Config{Host: "127.0.0.1", Port: 20200}); err == nil {
		t.Fatal("expected error for empty private key")
	}
}
