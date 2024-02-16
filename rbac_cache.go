package rbac

import "fmt"

type EndpointAuthorizationCacheProvider struct {
	cache *LRUCache
	auth  AuthorizationProvider
}

func NewEndpointAuthorizationCacheProvider(cache *LRUCache, auth AuthorizationProvider) *EndpointAuthorizationCacheProvider {
	return &EndpointAuthorizationCacheProvider{
		cache: cache,
		auth:  auth,
	}
}

func (e EndpointAuthorizationCacheProvider) IsAuthorized(entity EntityId, statement Statement) bool {
	key := fmt.Sprintf("%s:%s", entity, statement.String())
	if allowed, found := e.cache.Get(key); found {
		return allowed.(bool)
	}
	allowed := e.auth.IsAuthorized(entity, statement)
	e.cache.Put(key, allowed)
	return allowed
}
