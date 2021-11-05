package g8

import (
	"testing"
	"time"

	"github.com/TwiN/gocache/v2"
)

var (
	getClientByTokenFunc = func(token string) *Client {
		if token == "valid-token" {
			return &Client{Token: token}
		}
		return nil
	}
)

func TestClientProvider_GetClientByToken(t *testing.T) {
	provider := NewClientProvider(getClientByTokenFunc)
	if client := provider.GetClientByToken("valid-token"); client == nil {
		t.Error("should've returned a client")
	}
	if client := provider.GetClientByToken("invalid-token"); client != nil {
		t.Error("should've returned nil")
	}
}

func TestClientProvider_WithCache(t *testing.T) {
	provider := NewClientProvider(getClientByTokenFunc).WithCache(gocache.NoExpiration, 10000)
	if provider.cache.Count() != 0 {
		t.Error("expected cache to be empty")
	}
	if client := provider.GetClientByToken("valid-token"); client == nil {
		t.Error("expected client, got nil")
	}
	if provider.cache.Count() != 1 {
		t.Error("expected cache size to be 1")
	}
	if client := provider.GetClientByToken("valid-token"); client == nil {
		t.Error("expected client, got nil")
	}
	if provider.cache.Count() != 1 {
		t.Error("expected cache size to be 1")
	}
	if client := provider.GetClientByToken("invalid-token"); client != nil {
		t.Error("expected nil, got", client)
	}
	if provider.cache.Count() != 2 {
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
	if provider.cache.Count() != 1 {
		t.Error("expected cache size to be 1")
	}
	if provider.cache.Stats().ExpiredKeys != 0 {
		t.Error("expected cache statistics to report 0 expired key")
	}
	time.Sleep(15 * time.Millisecond)
	provider.GetClientByToken("token")
	if provider.cache.Stats().ExpiredKeys != 1 {
		t.Error("expected cache statistics to report 1 expired key")
	}
}

func TestClientProvider_WithCacheAndJanitor(t *testing.T) {
	provider := NewClientProvider(getClientByTokenFunc).WithCache(5*time.Millisecond, 10)
	provider.GetClientByToken("token")
	if provider.cache.Count() != 1 {
		t.Error("expected cache size to be 1")
	}
	provider.StartCacheJanitor()
	keyExpiredWithinOneSecond := false
	for start := time.Now(); time.Since(start) < time.Second; {
		if provider.cache.Stats().ExpiredKeys == 1 {
			keyExpiredWithinOneSecond = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !keyExpiredWithinOneSecond || provider.cache.Count() != 0 {
		t.Error("expected janitor to delete expired key")
	}
	provider.StopCacheJanitor()
}

func TestClientProvider_StartCacheJanitorWhenTTLSetToNoExpiration(t *testing.T) {
	provider := NewClientProvider(getClientByTokenFunc).WithCache(gocache.NoExpiration, 10)
	err := provider.StartCacheJanitor()
	if err != ErrNoExpiration {
		t.Error("expected provider.StartCacheJanitor() to return ErrNoExpiration, got", err)
	}
}

func TestClientProvider_StartCacheJanitorWhenCacheNotInitialized(t *testing.T) {
	provider := NewClientProvider(getClientByTokenFunc)
	err := provider.StartCacheJanitor()
	if err != ErrCacheNotInitialized {
		t.Error("expected provider.StartCacheJanitor() to return ErrCacheNotInitialized, got", err)
	}
}
