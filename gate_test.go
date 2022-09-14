package g8

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func (handler *testHandler) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func testHandlerFunc(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func TestUsability(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))

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

func TestNewGate(t *testing.T) {
	gate := NewGate(nil)
	if gate == nil {
		t.Error("gate should not be nil")
	}
}

func TestUnprotectedHandler(t *testing.T) {
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
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
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
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
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectMultipleTimes(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))
	badRequest, _ := http.NewRequest("GET", "/handle", http.NoBody)
	badRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))

	for i := 0; i < 100; i++ {
		responseRecorder := httptest.NewRecorder()
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusOK {
			t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
		}
		responseRecorder = httptest.NewRecorder()
		router.ServeHTTP(responseRecorder, badRequest)
		if responseRecorder.Code != http.StatusUnauthorized {
			t.Errorf("%s %s should have returned %d, but returned %d instead", badRequest.Method, badRequest.URL, http.StatusOK, responseRecorder.Code)
		}
	}
}

func TestGate_ProtectWithValidTokenExposedThroughClientProvider(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClientProvider(mockClientProvider))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", TestProviderToken))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithValidTokenExposedThroughClientProviderWithCache(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClientProvider(mockClientProvider.WithCache(60*time.Minute, 70000)))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
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
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClientProvider(mockClientProvider))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
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
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClientProvider(mockClientProvider))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
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
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClientProvider(mockClientProvider))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
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
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClient("token").WithPermission("admin")))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
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
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClientWithPermissions("token", []string{"mod"})))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermissions(&testHandler{}, []string{"admin"}))
	router.ServeHTTP(responseRecorder, request)

	// Since the client registered directly in the AuthorizationService has the permission "mod" and the
	// testHandler is protected by the permission "admin", the request should be not be authorized
	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_ProtectWithPermissions(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClient("mytoken").WithPermissions([]string{"create", "read", "update", "delete"})))

	router := http.NewServeMux()
	router.Handle("/create", gate.ProtectWithPermissions(&testHandler{}, []string{"create"}))
	router.Handle("/read", gate.ProtectWithPermissions(&testHandler{}, []string{"read"}))
	router.Handle("/update", gate.ProtectWithPermissions(&testHandler{}, []string{"update"}))
	router.Handle("/delete", gate.ProtectWithPermissions(&testHandler{}, []string{"delete"}))
	router.Handle("/crud", gate.ProtectWithPermissions(&testHandler{}, []string{"create", "read", "update", "delete"}))
	router.Handle("/backup", gate.ProtectWithPermissions(&testHandler{}, []string{"read", "backup"}))

	checkRouterOutput := func(t *testing.T, router *http.ServeMux, url string, expectedResponseCode int) {
		t.Run(strings.TrimPrefix(url, "/"), func(t *testing.T) {
			request, _ := http.NewRequest("GET", url, http.NoBody)
			request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "mytoken"))
			responseRecorder := httptest.NewRecorder()
			router.ServeHTTP(responseRecorder, request)
			if responseRecorder.Code != expectedResponseCode {
				t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, expectedResponseCode, responseRecorder.Code)
			}
		})
	}

	checkRouterOutput(t, router, "/create", http.StatusOK)
	checkRouterOutput(t, router, "/read", http.StatusOK)
	checkRouterOutput(t, router, "/update", http.StatusOK)
	checkRouterOutput(t, router, "/delete", http.StatusOK)
	checkRouterOutput(t, router, "/crud", http.StatusOK)
	checkRouterOutput(t, router, "/backup", http.StatusUnauthorized)
}

func TestGate_ProtectWithPermissionWhenClientHasSufficientPermissions(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClient("token").WithPermission("admin")))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermission(&testHandler{}, "admin"))
	router.ServeHTTP(responseRecorder, request)

	// Since the client registered directly in the AuthorizationService has the permission "admin" and the testHandler
	// is protected by the permission "admin", the request should be authorized
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithPermissionWhenClientHasInsufficientPermissions(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClientWithPermissions("token", []string{"mod"})))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermission(&testHandler{}, "admin"))
	router.ServeHTTP(responseRecorder, request)

	// Since the client registered directly in the AuthorizationService has the permission "mod" and the
	// testHandler is protected by the permission "admin", the request should be not be authorized
	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_PermissionMiddlewareWhenClientHasSufficientPermissions(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClient("token").WithPermission("admin")))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.PermissionMiddleware("admin")(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	// Since the client registered directly in the AuthorizationService has the permission "admin" and the testHandler
	// is protected by the permission "admin", the request should be authorized
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_PermissionMiddlewareWhenClientHasInsufficientPermissions(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClientWithPermissions("token", []string{"mod"})))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.PermissionMiddleware("admin")(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	// Since the client registered directly in the AuthorizationService has the permission "mod" and the
	// testHandler is protected by the permission "admin", the request should be not be authorized
	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_ProtectFuncWithInvalidToken(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
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
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectFunc(testHandlerFunc))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectFuncWithPermissionWhenClientHasSufficientPermissions(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClient("token").WithPermission("admin")))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.HandleFunc("/handle", gate.ProtectFuncWithPermission(testHandlerFunc, "admin"))
	router.ServeHTTP(responseRecorder, request)

	// Since the client registered directly in the AuthorizationService has the permission "admin" and the testHandler
	// is protected by the permission "admin", the request should be authorized
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectFuncWithPermissionWhenClientHasInsufficientPermissions(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClientWithPermissions("token", []string{"mod"})))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.HandleFunc("/handle", gate.ProtectFuncWithPermission(testHandlerFunc, "admin"))
	router.ServeHTTP(responseRecorder, request)

	// Since the client registered directly in the AuthorizationService has the permission "mod" and the
	// testHandler is protected by the permission "admin", the request should be not be authorized
	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_WithCustomUnauthorizedResponseBody(t *testing.T) {
	gate := New().WithAuthorizationService(NewAuthorizationService()).WithCustomUnauthorizedResponseBody([]byte("test"))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
	if responseBody, _ := io.ReadAll(responseRecorder.Body); string(responseBody) != "test" {
		t.Errorf("%s %s should have returned %s, but returned %s instead", request.Method, request.URL, "test", string(responseBody))
	}
}

func TestGate_ProtectWithNoAuthorizationService(t *testing.T) {
	gate := New()
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithRateLimit(t *testing.T) {
	gate := New().WithRateLimit(2)
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(&testHandler{}))

	responseRecorder := httptest.NewRecorder()
	router.ServeHTTP(responseRecorder, request)
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}

	responseRecorder = httptest.NewRecorder()
	router.ServeHTTP(responseRecorder, request)
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}

	responseRecorder = httptest.NewRecorder()
	router.ServeHTTP(responseRecorder, request)
	if responseRecorder.Code != http.StatusTooManyRequests {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusTooManyRequests, responseRecorder.Code)
	}

	// Wait for rate limit time window to pass
	time.Sleep(time.Second)

	responseRecorder = httptest.NewRecorder()
	router.ServeHTTP(responseRecorder, request)
	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_WithCustomTokenExtractor(t *testing.T) {
	authorizationService := NewAuthorizationService().WithClientProvider(mockClientProvider)
	customTokenExtractorFunc := func(request *http.Request) string {
		sessionCookie, err := request.Cookie("session")
		if err != nil {
			return ""
		}
		return sessionCookie.Value
	}
	gate := New().WithAuthorizationService(authorizationService).WithCustomTokenExtractor(customTokenExtractorFunc)

	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.AddCookie(&http.Cookie{Name: "session", Value: TestProviderToken})
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(TokenContextKey) != TestProviderToken {
			t.Errorf("token should have been passed to the request context")
		}
		w.WriteHeader(http.StatusOK)
	}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGateWithCustomHeader(t *testing.T) {
	authorizationService := NewAuthorizationService().WithClientProvider(mockClientProvider)
	customTokenExtractorFunc := func(request *http.Request) string {
		return request.Header.Get("X-API-Token")
	}
	gate := New().WithAuthorizationService(authorizationService).WithCustomTokenExtractor(customTokenExtractorFunc)

	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("X-API-Token", TestProviderToken)
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(TokenContextKey) != TestProviderToken {
			t.Errorf("token should have been passed to the request context")
		}
		w.WriteHeader(http.StatusOK)
	}))
	router.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}
