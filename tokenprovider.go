package g8

type TokenProvider struct {
	cacheTokens bool

	tokenExistsFunc func(token string) bool
}

func NewTokenProvider(tokenExistsFunc func(token string) bool) *TokenProvider {
	return &TokenProvider{
		cacheTokens:     false,
		tokenExistsFunc: tokenExistsFunc,
	}
}

func (provider *TokenProvider) Exists(token string) bool {
	return provider.tokenExistsFunc(token)
}
