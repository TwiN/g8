package g8

import (
	"sync"
	"testing"
	"time"

	"github.com/TwiN/gocache/v2"
)

var (
	getClientByTokenFunc = func(token string) *Client {
		if token == "valid-token" {
			return NewClient("valid-token").WithData("client-data")
		}
		return nil
	}
)

func TestClientProvider_GetClientByToken(t *testing.T) {
	provider := NewClientProvider(getClientByTokenFunc)
	if client := provider.GetClientByToken("valid-token"); client == nil {
		t.Error("should've returned a client")
	} else if client.Data != "client-data" {
		t.Error("expected client data to be 'client-data', got", client.Data)
	}
	if client := provider.GetClientByToken("invalid-token"); client != nil {
		t.Error("should've returned nil")
	}
}

func TestClientProvider_WithCache(t *testing.T) {
	provider := NewClientProvider(getClientByTokenFunc).WithCache(gocache.NoExpiration, 10000)
	if provider.cache.(*gocache.Cache).Count() != 0 {
		t.Error("expected cache to be empty")
	}
	if client := provider.GetClientByToken("valid-token"); client == nil {
		t.Error("expected client, got nil")
	}
	if provider.cache.(*gocache.Cache).Count() != 1 {
		t.Error("expected cache size to be 1")
	}
	if client := provider.GetClientByToken("valid-token"); client == nil {
		t.Error("expected client, got nil")
	}
	if provider.cache.(*gocache.Cache).Count() != 1 {
		t.Error("expected cache size to be 1")
	}
	if client := provider.GetClientByToken("invalid-token"); client != nil {
		t.Error("expected nil, got", client)
	}
	if provider.cache.(*gocache.Cache).Count() != 2 {
		t.Error("expected cache size to be 2")
	}
	if client := provider.GetClientByToken("invalid-token"); client != nil {
		t.Error("expected nil, got", client)
	}
	if client := provider.GetClientByToken("invalid-token"); client != nil {
		t.Error("should've returned nil (cached)")
	}
}

func TestClientProvider_WithCacheAndExpiration(t *testing.T) {
	provider := NewClientProvider(getClientByTokenFunc).WithCache(10*time.Millisecond, 10)
	provider.GetClientByToken("token")
	if provider.cache.(*gocache.Cache).Count() != 1 {
		t.Error("expected cache size to be 1")
	}
	if provider.cache.(*gocache.Cache).Stats().ExpiredKeys != 0 {
		t.Error("expected cache statistics to report 0 expired key")
	}
	time.Sleep(15 * time.Millisecond)
	provider.GetClientByToken("token")
	if provider.cache.(*gocache.Cache).Stats().ExpiredKeys != 1 {
		t.Error("expected cache statistics to report 1 expired key")
	}
}

type customCache struct {
	entries map[string]any
	sync.Mutex
}

func (c *customCache) Get(key string) (value any, exists bool) {
	c.Lock()
	v, exists := c.entries[key]
	c.Unlock()
	return v, exists
}

func (c *customCache) Set(key string, value any) {
	c.Lock()
	if c.entries == nil {
		c.entries = make(map[string]any)
	}
	c.entries[key] = value
	c.Unlock()
}

var _ Cache = (*customCache)(nil)

func TestClientProvider_WithCustomCache(t *testing.T) {
	provider := NewClientProvider(getClientByTokenFunc).WithCustomCache(&customCache{})
	if len(provider.cache.(*customCache).entries) != 0 {
		t.Error("expected cache to be empty")
	}
	if client := provider.GetClientByToken("valid-token"); client == nil {
		t.Error("expected client, got nil")
	}
	if len(provider.cache.(*customCache).entries) != 1 {
		t.Error("expected cache size to be 1")
	}
	if client := provider.GetClientByToken("valid-token"); client == nil {
		t.Error("expected client, got nil")
	}
	if len(provider.cache.(*customCache).entries) != 1 {
		t.Error("expected cache size to be 1")
	}
	if client := provider.GetClientByToken("invalid-token"); client != nil {
		t.Error("expected nil, got", client)
	}
	if len(provider.cache.(*customCache).entries) != 2 {
		t.Error("expected cache size to be 2")
	}
	if client := provider.GetClientByToken("invalid-token"); client != nil {
		t.Error("expected nil, got", client)
	}
	if client := provider.GetClientByToken("invalid-token"); client != nil {
		t.Error("should've returned nil (cached)")
	}
}
