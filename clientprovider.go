package g8

import (
	"time"

	"github.com/TwiN/gocache/v2"
)

// ClientProvider has the task of retrieving a Client from an external source (e.g. a database) when provided with a
// token. It should be used when you have a lot of tokens, and it wouldn't make sense to register all of them using
// AuthorizationService's WithToken, WithTokens, WithClient or WithClients.
//
// Note that the provider is used as a fallback source. As such, if a token is explicitly registered using one of the 4
// aforementioned functions, the client provider will not be used by the AuthorizationService when a request is made
// with said token. It will, however, be called upon if a token that is not explicitly registered in
// AuthorizationService is sent alongside a request going through the Gate.
//
//	clientProvider := g8.NewClientProvider(func(token string) *g8.Client {
//	    // We'll assume that the following function calls your database and returns a struct "User" that
//	    // has the user's token as well as the permissions granted to said user
//	    user := database.GetUserByToken(token)
//	    if user != nil {
//	        return g8.NewClient(user.Token).WithPermissions(user.Permissions)
//	    }
//	    return nil
//	})
//	gate := g8.New().WithAuthorizationService(g8.NewAuthorizationService().WithClientProvider(clientProvider))
type ClientProvider struct {
	getClientByTokenFunc func(token string) *Client

	cache Cache
}

// NewClientProvider creates a ClientProvider
// The parameter that must be passed is a function that the provider will use to retrieve a client by a given token
//
// Example:
//
//	clientProvider := g8.NewClientProvider(func(token string) *g8.Client {
//	    // We'll assume that the following function calls your database and returns a struct "User" that
//	    // has the user's token as well as the permissions granted to said user
//	    user := database.GetUserByToken(token)
//	    if user == nil {
//	        return nil
//	    }
//	    return g8.NewClient(user.Token).WithPermissions(user.Permissions)
//	})
//	gate := g8.New().WithAuthorizationService(g8.NewAuthorizationService().WithClientProvider(clientProvider))
func NewClientProvider(getClientByTokenFunc func(token string) *Client) *ClientProvider {
	return &ClientProvider{
		getClientByTokenFunc: getClientByTokenFunc,
	}
}

// WithCache enables an in-memory cache for the ClientProvider.
//
// Example:
//
//	clientProvider := g8.NewClientProvider(func(token string) *g8.Client {
//	    // We'll assume that the following function calls your database and returns a struct "User" that
//	    // has the user's token as well as the permissions granted to said user
//	    user := database.GetUserByToken(token)
//	    if user != nil {
//	        return g8.NewClient(user.Token).WithPermissions(user.Permissions)
//	    }
//	    return nil
//	})
//	gate := g8.New().WithAuthorizationService(g8.NewAuthorizationService().WithClientProvider(clientProvider.WithCache(time.Hour, 70000)))
func (provider *ClientProvider) WithCache(ttl time.Duration, maxSize int) *ClientProvider {
	return provider.WithCustomCache(
		gocache.NewCache().WithEvictionPolicy(gocache.LeastRecentlyUsed).WithMaxSize(maxSize).WithDefaultTTL(ttl),
	)
}

// WithCustomCache allows you to use a custom cache implementation instead of the default one.
// By default, using WithCache will leverage gocache.
//
// Note that the custom cache must implement the Cache interface
func (provider *ClientProvider) WithCustomCache(cache Cache) *ClientProvider {
	provider.cache = cache
	return provider
}

// GetClientByToken retrieves a client by its token through the provided getClientByTokenFunc.
func (provider *ClientProvider) GetClientByToken(token string) *Client {
	if provider.cache == nil {
		return provider.getClientByTokenFunc(token)
	}
	if cachedClient, exists := provider.cache.Get(token); exists {
		if cachedClient == nil {
			return nil
		}
		// Safely typecast the client.
		// Regardless of whether the typecast is successful or not, we return client since it'll be either client or
		// nil. Technically, it should never be nil, but it's better to be safe than sorry.
		client, _ := cachedClient.(*Client)
		return client
	}
	client := provider.getClientByTokenFunc(token)
	provider.cache.Set(token, client)
	return client
}
