package rbac

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEndpointAuthorizationProviderIsAuthorized(t *testing.T) {
	mockStore := MockUserStore{}
	authProvider := NewEndpointAuthorizationProvider(mockStore)

	entityID := EntityId("entity1")
	statement := NewEndpointStatement(ENV_PROD, METHOD_GET, ENDPOINT_EXAMPLE, EFFECT_ALLOW)

	authorized := authProvider.IsAuthorized(entityID, statement)

	if !authorized {
		t.Errorf("Expected entity %s to be authorized", entityID)
	}
}

func TestEndpointAuthorizationProviderIsNotAuthorized(t *testing.T) {
	mockStore := MockUserStore{}
	authProvider := NewEndpointAuthorizationProvider(mockStore)

	entityID := EntityId("entity2")
	statement := NewEndpointStatement(ENV_PROD, METHOD_GET, ENDPOINT_EXAMPLE, EFFECT_ALLOW)

	authorized := authProvider.IsAuthorized(entityID, statement)

	if authorized {
		t.Errorf("Expected entity %s to not be authorized", entityID)
	}
}

func TestAuthorizationMiddleware(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/example", func(w http.ResponseWriter, r *http.Request) {})

	wrappedMux := AuthorizationMiddleware(NewEndpointAuthorizationProvider(MockUserStore{}))(mux)

	req, err := http.NewRequest("GET", "/example", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Entity-ID", "entity1")

	recorder := httptest.NewRecorder()
	wrappedMux.ServeHTTP(recorder, req)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAuthorizationMiddlewareDeny(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/example", func(w http.ResponseWriter, r *http.Request) {})

	wrappedMux := AuthorizationMiddleware(NewEndpointAuthorizationProvider(MockUserStore{}))(mux)

	req, err := http.NewRequest("GET", "/example", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Entity-ID", "entity2")

	recorder := httptest.NewRecorder()
	wrappedMux.ServeHTTP(recorder, req)

	if status := recorder.Code; status != http.StatusForbidden {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
	}
}
