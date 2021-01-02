package g8

type ClientProvider struct {
	cache bool

	getClientByTokenFunc func(token string) *Client
}

func NewClientProvider(getClientByTokenFunc func(token string) *Client) *ClientProvider {
	return &ClientProvider{
		cache:                false,
		getClientByTokenFunc: getClientByTokenFunc,
	}
}

func (provider *ClientProvider) GetClientByToken(token string) *Client {
	return provider.getClientByTokenFunc(token)
}
