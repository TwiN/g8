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

	router := http.NewServeMux()
	router.Handle("/handle", handler)

	for n := 0; n < b.N; n++ {
		responseRecorder := httptest.NewRecorder()
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusOK {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWhenNoAuthorizationHeader(b *testing.B) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	for n := 0; n < b.N; n++ {
		responseRecorder := httptest.NewRecorder()
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusUnauthorized {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithInvalidToken(b *testing.B) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	for n := 0; n < b.N; n++ {
		responseRecorder := httptest.NewRecorder()
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusUnauthorized {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithValidToken(b *testing.B) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	for n := 0; n < b.N; n++ {
		responseRecorder := httptest.NewRecorder()
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusOK {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithPermissionsAndValidToken(b *testing.B) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClient("token").WithPermission("admin")))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermissions(handler, []string{"admin"}))

	for n := 0; n < b.N; n++ {
		responseRecorder := httptest.NewRecorder()
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusOK {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithPermissionsAndValidTokenButInsufficientPermissions(b *testing.B) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClient(NewClient("token").WithPermission("mod")))
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "token"))

	router := http.NewServeMux()
	router.Handle("/handle", gate.ProtectWithPermissions(handler, []string{"admin"}))

	for n := 0; n < b.N; n++ {
		responseRecorder := httptest.NewRecorder()
		router.ServeHTTP(responseRecorder, request)
		if responseRecorder.Code != http.StatusUnauthorized {
			b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusUnauthorized, responseRecorder.Code)
		}
	}
	b.ReportAllocs()
}

func BenchmarkGate_ProtectConcurrently(b *testing.B) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token"))

	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "good-token"))

	badRequest, _ := http.NewRequest("GET", "/handle", http.NoBody)
	badRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "bad-token"))

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			responseRecorder := httptest.NewRecorder()
			router.ServeHTTP(responseRecorder, request)
			if responseRecorder.Code != http.StatusOK {
				b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
			}
			responseRecorder = httptest.NewRecorder()
			router.ServeHTTP(responseRecorder, badRequest)
			if responseRecorder.Code != http.StatusUnauthorized {
				b.Fatalf("%s %s should have returned %d, but returned %d instead", badRequest.Method, badRequest.URL, http.StatusUnauthorized, responseRecorder.Code)
			}
		}
	})
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithClientProviderConcurrently(b *testing.B) {
	gate := New().WithAuthorizationService(NewAuthorizationService().WithClientProvider(mockClientProvider))

	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", TestProviderToken))

	firstBadRequest, _ := http.NewRequest("GET", "/handle", http.NoBody)
	firstBadRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", "bad-token-1"))

	secondBadRequest, _ := http.NewRequest("GET", "/handle", http.NoBody)
	secondBadRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", "bad-token-2"))

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			responseRecorder := httptest.NewRecorder()
			router.ServeHTTP(responseRecorder, request)
			if responseRecorder.Code != http.StatusOK {
				b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
			}
			responseRecorder = httptest.NewRecorder()
			router.ServeHTTP(responseRecorder, firstBadRequest)
			if responseRecorder.Code != http.StatusUnauthorized {
				b.Fatalf("%s %s should have returned %d, but returned %d instead", firstBadRequest.Method, firstBadRequest.URL, http.StatusUnauthorized, responseRecorder.Code)
			}
			responseRecorder = httptest.NewRecorder()
			router.ServeHTTP(responseRecorder, secondBadRequest)
			if responseRecorder.Code != http.StatusUnauthorized {
				b.Fatalf("%s %s should have returned %d, but returned %d instead", secondBadRequest.Method, secondBadRequest.URL, http.StatusUnauthorized, responseRecorder.Code)
			}
		}
	})
	b.ReportAllocs()
}

func BenchmarkGate_ProtectWithValidTokenAndCustomTokenExtractorFuncConcurrently(b *testing.B) {
	customTokenExtractorFunc := func(request *http.Request) string {
		sessionCookie, err := request.Cookie("session")
		if err != nil {
			return ""
		}
		return sessionCookie.Value
	}
	gate := New().WithAuthorizationService(NewAuthorizationService().WithToken("good-token")).WithCustomTokenExtractor(customTokenExtractorFunc)
	request, _ := http.NewRequest("GET", "/handle", http.NoBody)
	request.AddCookie(&http.Cookie{Name: "session", Value: "good-token"})

	router := http.NewServeMux()
	router.Handle("/handle", gate.Protect(handler))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			responseRecorder := httptest.NewRecorder()
			router.ServeHTTP(responseRecorder, request)
			if responseRecorder.Code != http.StatusOK {
				b.Fatalf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, http.StatusOK, responseRecorder.Code)
			}
		}
	})
	b.ReportAllocs()
}
