package rbac

import (
	"fmt"
	"testing"
	"time"
)

type MockEndpointAuthorizationProvider struct {
	authorizedResponses map[string]bool
}

func (m *MockEndpointAuthorizationProvider) IsAuthorized(entity EntityId, statement Statement) bool {
	key := fmt.Sprintf("%s:%s", entity, statement.String())
	allowed, exists := m.authorizedResponses[key]
	if !exists {
		return false
	}
	return allowed
}

type MockStatement struct {
	Action string
}

func (m MockStatement) String() string {
	return m.Action
}

func NewMockStatement(action string) Statement {
	return MockStatement{Action: action}
}

func TestEndpointAuthorizationCacheProvider_IsAuthorized(t *testing.T) {
	cache := NewLRUCache(10, 5*time.Minute)
	mockAuth := &MockEndpointAuthorizationProvider{
		authorizedResponses: map[string]bool{
			"entity1:action1": true,
			"entity2:action2": false,
		},
	}
	provider := NewEndpointAuthorizationCacheProvider(cache, mockAuth)

	tests := []struct {
		entity   EntityId
		action   string
		expected bool
	}{
		{"entity1", "action1", true},
		{"entity2", "action2", false},
		{"entity3", "action3", false},
	}

	for _, test := range tests {
		statement := NewMockStatement(test.action)
		result := provider.IsAuthorized(test.entity, statement)
		if result != test.expected {
			t.Errorf("IsAuthorized(%s, %s) = %t; want %t", test.entity, test.action, result, test.expected)
		}
	}

	mockAuth.authorizedResponses["entity1:action1"] = false
	mockAuth.authorizedResponses["entity2:action2"] = true

	for _, test := range tests {
		statement := NewMockStatement(test.action)
		result := provider.IsAuthorized(test.entity, statement)
		if result != test.expected {
			t.Errorf("Cached IsAuthorized(%s, %s) = %t; want cached result %t", test.entity, test.action, result, test.expected)
		}
	}
}
