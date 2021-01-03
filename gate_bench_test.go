package g8

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

var handler http.Handler = &testHandler{}

func BenchmarkTestHandler(b *testing.B) {
	request, _ := http.NewRequest("GET", "/handle", nil)
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", handler)

	for n := 0; n < b.N; n++ {
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusOK {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWhenNoAuthorizationHeader(b *testing.B) {
	gate := NewGate(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	for n := 0; n < b.N; n++ {
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusUnauthorized {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithInvalidToken(b *testing.B) {
	gate := NewGate(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	for n := 0; n < b.N; n++ {
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusUnauthorized {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithValidToken(b *testing.B) {
	gate := NewGate(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	for n := 0; n < b.N; n++ {
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusOK {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithPermissionsAndValidToken(b *testing.B) {
	gate := NewGate(NewAuthorizationService().WithClient(NewClient("token").WithPermission("admin")))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermissions(handler, []string{"admin"}))

	for n := 0; n < b.N; n++ {
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusOK {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithPermissionsAndValidTokenButInsufficientPermissions(b *testing.B) {
	gate := NewGate(NewAuthorizationService().WithClient(NewClient("token").WithPermission("mod")))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermissions(handler, []string{"admin"}))

	for n := 0; n < b.N; n++ {
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusUnauthorized {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithValidTokenConcurrently(b *testing.B) {
	gate := NewGate(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))
	responseRecorder := httptest.NewRecorder()

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			router.ServeHTTP(responseRecorder, request)
			if responseRecorder.Code != http.StatusOK {
				b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
			}
		}
	})
	b.ReportAllocs()
}
