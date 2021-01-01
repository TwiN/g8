package g8

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testHandler struct {
}

func (handler *testHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

//func testHandlerFunc(handler http.Handler) http.Handler {
//	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
//		writer.WriteHeader(http.StatusOK)
//	})
//}

func TestUnprotectedHandler(t *testing.T) {
	request, _ := http.NewRequest("", "", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))
	responseRecorder := httptest.NewRecorder()

	handler := &testHandler{}
	handler.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithInvalidToken(t *testing.T) {
	gate := NewGate().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("", "", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))
	responseRecorder := httptest.NewRecorder()

	var handler http.Handler = &testHandler{}
	handler = gate.Protect(handler)
	handler.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}

func TestGate_ProtectWithValidToken(t *testing.T) {
	gate := NewGate().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("", "", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))
	responseRecorder := httptest.NewRecorder()

	var handler http.Handler = &testHandler{}
	handler = gate.Protect(handler)
	handler.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithValidTokenExposedThroughTokenProvider(t *testing.T) {
	gate := NewGate().WithAuthorizationService(NewAuthorizationService().WithTokenProvider(NewTokenProvider(func(token string) bool {
		return token == "token-from-provider"
	})))
	request, _ := http.NewRequest("", "", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token-from-provider"))
	responseRecorder := httptest.NewRecorder()

	var handler http.Handler = &testHandler{}
	handler = gate.Protect(handler)
	handler.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusOK {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
	}
}

func TestGate_ProtectWithInvalidTokenWhenUsingTokenProvider(t *testing.T) {
	gate := NewGate().WithAuthorizationService(NewAuthorizationService().WithTokenProvider(NewTokenProvider(func(token string) bool {
		return token == "token-from-provider"
	})))
	request, _ := http.NewRequest("", "", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))
	responseRecorder := httptest.NewRecorder()

	var handler http.Handler = &testHandler{}
	handler = gate.Protect(handler)
	handler.ServeHTTP(responseRecorder, request)

	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
	}
}
