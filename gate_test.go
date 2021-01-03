package g8

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	FirstTestProviderClientPermission  = "permission-1"
	SecondTestProviderClientPermission = "permission-2"
	TestProviderToken                  = "token-from-provider"
)

var (
	mockClientProvider = NewClientProvider(func(token string) *Client {
		// We'll pretend that there's only one token that's valid in the client provider, every other token
		// returns nil
		if token == TestProviderToken {
			return &Client{
				Token:       TestProviderToken,
				Permissions: []string{FirstTestProviderClientPermission, SecondTestProviderClientPermission},
			}
		}
		return nil
	})
)

type testHandler struct {
}

func (handler *testHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func testHandlerFunc(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func TestUsability(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithToken("good-token"))

	var handler http.Handler = &testHandler{}
	handlerFunc := func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}

	router := http.NewServeMux()
	router.Handle("/handle", handler)
	router.Handle("/handle-protected", gate.Protect(handler))
	router.HandleFunc("/handlefunc", handlerFunc)
	router.HandleFunc("/handlefunc-protected", gate.ProtectFunc(handlerFunc))
}

func TestUnprotectedHandler(t *testing.T) {
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", &testHandler{})
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithInvalidToken(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_ProtectWithValidToken(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithValidTokenExposedThroughClientProvider(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithClientProvider(mockClientProvider))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", TestProviderToken))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithInvalidTokenWhenUsingClientProvider(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithClientProvider(mockClientProvider))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_ProtectWithPermissionsWhenValidTokenAndSufficientPermissionsWhileUsingClientProvider(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithClientProvider(mockClientProvider))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", TestProviderToken))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermissions(&testHandler{}, []string{SecondTestProviderClientPermission}))
	router.ServeHTTP(responseRecorder, request)

	// Since the client returned from the mockClientProvider has FirstTestProviderClientPermission and
	// SecondTestProviderClientPermission and the testHandler is protected by SecondTestProviderClientPermission,
	// the request should be authorized
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithPermissionsWhenValidTokenAndInsufficientPermissionsWhileUsingClientProvider(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithClientProvider(mockClientProvider))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", TestProviderToken))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermissions(&testHandler{}, []string{"unrelated-permission"}))
	router.ServeHTTP(responseRecorder, request)

	// Since the client returned from the mockClientProvider has FirstTestProviderClientPermission and
	// SecondTestProviderClientPermission and the testHandler is protected by a permission that the client does not
	// have, the request should be not be authorized
	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_ProtectWithPermissionsWhenClientHasSufficientPermissions(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithClient(NewClient("token").WithPermission("admin")))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermissions(&testHandler{}, []string{"admin"}))
	router.ServeHTTP(responseRecorder, request)

	// Since the client registered directly in the AuthorizationService has the permission "admin" and the testHandler
	// is protected by the permission "admin", the request should be authorized
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithPermissionsWhenClientHasInsufficientPermissions(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithClient(NewClientWithPermissions("token", []string{"moderator"})))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermissions(&testHandler{}, []string{"administrator"}))
	router.ServeHTTP(responseRecorder, request)

	// Since the client registered directly in the AuthorizationService has the permission "moderator" and the
	// testHandler is protected by the permission "administrator", the request should be not be authorized
	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_ProtectFuncWithInvalidToken(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectFunc(testHandlerFunc))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_ProtectFuncWithValidToken(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectFunc(testHandlerFunc))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithPermissions(t *testing.T) {
	gate := NewGate(NewAuthorizationService().WithClient(NewClient("mytoken").WithPermissions([]string{"create", "read", "update", "delete"})))

	router := http.NewServeMux()
	router.Handle("/create", gate.ProtectWithPermissions(&testHandler{}, []string{"create"}))
	router.Handle("/read", gate.ProtectWithPermissions(&testHandler{}, []string{"read"}))
	router.Handle("/update", gate.ProtectWithPermissions(&testHandler{}, []string{"update"}))
	router.Handle("/delete", gate.ProtectWithPermissions(&testHandler{}, []string{"delete"}))
	router.Handle("/crud", gate.ProtectWithPermissions(&testHandler{}, []string{"create", "read", "update", "delete"}))
	router.Handle("/backup", gate.ProtectWithPermissions(&testHandler{}, []string{"read", "backup"}))

	checkRouterOutput(t, router, "/create", http.StatusOK)
	checkRouterOutput(t, router, "/read", http.StatusOK)
	checkRouterOutput(t, router, "/update", http.StatusOK)
	checkRouterOutput(t, router, "/delete", http.StatusOK)
	checkRouterOutput(t, router, "/crud", http.StatusOK)
	checkRouterOutput(t, router, "/backup", http.StatusUnauthorized)
}

func checkRouterOutput(t *testing.T, router *http.ServeMux, url string, expectedResponseCode int) {
	t.Run(strings.TrimPrefix(url, "/"), func(t *testing.T) {
		request, _ := http.NewRequest("GET", url, nil)
		request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "mytoken"))
		responseRecorder := httptest.NewRecorder()
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != expectedResponseCode {
			t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, expectedResponseCode, responseRecorder.Code)
		}
	})
}
