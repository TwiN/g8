package g8

import (
	"time"

	"github.com/TwinProduction/gocache"
)

// ClientProvider has the task of retrieving a Client from an external source (e.g. a database) when provided with a
// token. It should be used when you have a lot of tokens and it wouldn't make sense to register all of them using
// AuthorizationService's WithToken, WithTokens, WithClient or WithClients.
//
// Note that the provider is used as a fallback source. As such, if a token is explicitly registered using one of the 4
// aforementioned functions, the client provider will not be used by the AuthorizationService when a request is made
// with said token. It will, however, be called upon if a token that is not explicitly registered in
// AuthorizationService is sent alongside a request going through the Gate.
//
//     clientProvider := g8.NewClientProvider(func(token string) *g8.Client {
//         // We'll assume that the following function calls your database and returns a struct "User" that
//         // has the user's token as well as the permissions granted to said user
//         user := database.GetUserByToken(token)
//         if user != nil {
//             return g8.NewClient(user.Token).WithPermissions(user.Permissions)
//         }
//         return nil
//     })
//     gate := g8.NewGate(g8.NewAuthorizationService().WithClientProvider(clientProvider))
//
type ClientProvider struct {
	cache                *gocache.Cache
	getClientByTokenFunc func(token string) *Client
	ttl                  time.Duration
}

// NewClientProvider creates a ClientProvider
// The parameter that must be passed is a function that the provider will use to retrieve a client by a given token
//
// Example:
//     clientProvider := g8.NewClientProvider(func(token string) *g8.Client {
//         // We'll assume that the following function calls your database and returns a struct "User" that
//         // has the user's token as well as the permissions granted to said user
//         user := database.GetUserByToken(token)
//         if user != nil {
//             return g8.NewClient(user.Token).WithPermissions(user.Permissions)
//         }
//         return nil
//     })
//     gate := g8.NewGate(g8.NewAuthorizationService().WithClientProvider(clientProvider))
func NewClientProvider(getClientByTokenFunc func(token string) *Client) *ClientProvider {
	return &ClientProvider{
		getClientByTokenFunc: getClientByTokenFunc,
	}
}

// WithCache adds cache options to the ClientProvider.
// ttl is the time until the cache entry will be deleted. A ttl of -1 means no expiration
// maxSize is the maximum amount of entries that can be in the cache at any given time. If a value of 0 or less is provided, it means
// infinite
//
// Example:
// 		 clientProvider := g8.NewClientProvider(func(token string) *g8.Client {
//         // We'll assume that the following function calls your database and returns a struct "User" that
//         // has the user's token as well as the permissions granted to said user
//         user := database.GetUserByToken(token)
//         if user != nil {
//             return g8.NewClient(user.Token).WithPermissions(user.Permissions)
//         }
//         return nil
// 			})
//     gate := g8.NewGate(g8.NewAuthorizationService().WithClientProvider(clientProvider.WithCache(60*time.Minute, 70000)))
func (provider *ClientProvider) WithCache(ttl time.Duration, maxSize int) *ClientProvider {
	provider.cache = gocache.NewCache().WithEvictionPolicy(gocache.LeastRecentlyUsed).WithMaxSize(maxSize)
	provider.cache.StartJanitor() // Passively manage expired entries

	provider.ttl = ttl
	return provider
}

// GetClientByToken retrieves a client by its token through the provided getClientByTokenFunc.
func (provider *ClientProvider) GetClientByToken(token string) *Client {
	// No need to go further if cache isn't enabled
	if provider.cache == nil {
		return provider.getClientByTokenFunc(token)
	}

	if value, exists := provider.cache.Get(token); value != nil && exists {
		return value.(*Client)
	}

	client := provider.getClientByTokenFunc(token)
	provider.cache.SetWithTTL(token, client, provider.ttl)

	return client
}
