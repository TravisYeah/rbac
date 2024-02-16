package rbac

import (
	"fmt"
	"net/http"
)

type Entity struct {
	Id EntityId
}

type EntityId string

type Tag struct {
	Id   string
	Name string
}

type Role struct {
	Name        string
	Description string
	Tags        []Tag
	Assigments  []EntityId
	Policies    []Policy
}

type Policy struct {
	Name        string
	Description string
	Statements  []Statement
}

type Statement interface {
	String() string
}

type Resource interface {
	Match(Resource) bool
	String() string
}

type Effect interface {
	Match(Effect) bool
	String() string
}

type Action interface {
	Match(Action) bool
	String() string
}

type Env string

const (
	ENV_DEV  Env = "DEV"
	ENV_PROD Env = "PROD"
)

type EndpointMethod string

const (
	METHOD_GET  EndpointMethod = "GET"
	METHOD_POST EndpointMethod = "POST"
)

type EndpointPath string

const (
	ENDPOINT_EXAMPLE EndpointPath = "/example"
)

type MethodEndpointResource struct {
	Method EndpointMethod
	Path   EndpointPath
}

func (m MethodEndpointResource) Match(resource Resource) bool {
	if r, ok := resource.(MethodEndpointResource); ok {
		return m.Method == r.Method && m.Path == r.Path
	}
	return false
}

func (m MethodEndpointResource) String() string {
	return fmt.Sprintf("%s:%s", m.Method, m.Path)
}

func NewMethodEndpointResource(method EndpointMethod, path EndpointPath) MethodEndpointResource {
	return MethodEndpointResource{
		Method: method,
		Path:   path,
	}
}

type EnvEndpointResource struct {
	Env      Env
	Resource MethodEndpointResource
}

func (e EnvEndpointResource) Match(resource Resource) bool {
	if r, ok := resource.(EnvEndpointResource); ok {
		return e.Env == r.Env && e.Resource == r.Resource
	}
	return false
}

func (e EnvEndpointResource) String() string {
	return fmt.Sprintf("%s:%s", e.Env, e.Resource)
}

func NewResource(env Env, method EndpointMethod, path EndpointPath) EnvEndpointResource {
	return EnvEndpointResource{
		Env:      env,
		Resource: NewMethodEndpointResource(method, path),
	}
}

type AllowDeny string

const (
	EFFECT_ALLOW AllowDeny = "ALLOW"
	EFFECT_DENY  AllowDeny = "DENY"
)

type AllowDenyEffect struct {
	Effect AllowDeny
}

func (a AllowDenyEffect) Match(effect Effect) bool {
	if e, ok := effect.(AllowDenyEffect); ok {
		return a.Effect == e.Effect
	}
	return false
}

func (a AllowDenyEffect) String() string {
	return string(a.Effect)
}

func NewEffect(effect AllowDeny) AllowDenyEffect {
	return AllowDenyEffect{
		Effect: effect,
	}
}

type CRUD string

const (
	CRUD_CREATE CRUD = "CREATE"
	CRUD_READ   CRUD = "READ"
	CRUD_UPDATE CRUD = "UPDATE"
	CRUD_DELETE CRUD = "DELETE"
)

type CRUDAction struct {
	Action CRUD
}

func (c CRUDAction) Match(action Action) bool {
	if a, ok := action.(CRUDAction); ok {
		return c.Action == a.Action
	}
	return false
}

func (c CRUDAction) String() string {
	return string(c.Action)
}

func NewAction(action CRUD) CRUDAction {
	return CRUDAction{
		Action: action,
	}
}

func NewPolicy(name string, description string, statements []Statement) Policy {
	return Policy{
		Name:        name,
		Description: description,
		Statements:  statements,
	}
}

func NewTag(id string, name string) Tag {
	return Tag{
		Id:   id,
		Name: name,
	}
}

func NewRole(name string, description string, tags []Tag, assigments []EntityId, policies []Policy) Role {
	return Role{
		Name:        name,
		Description: description,
		Tags:        tags,
		Assigments:  assigments,
		Policies:    policies,
	}
}

func (r Role) IsEntityAssigned(entityId EntityId) bool {
	for _, id := range r.Assigments {
		if id == entityId {
			return true
		}
	}
	return false
}

type AuthorizationProvider interface {
	IsAuthorized(entity EntityId, statement Statement) bool
}

type EndpointAuthorizationProvider struct {
	UserStore UserStore
}

func (e EndpointAuthorizationProvider) IsAuthorized(entity EntityId, statement Statement) bool {
	roles := e.UserStore.GetRoles(entity)

	allowed := false
	for _, role := range roles {
		for _, policy := range role.Policies {
			for _, statement := range policy.Statements {
				s, ok := statement.(EndpointStatement)
				if !ok {
					continue
				}
				if res := s.Allowed(statement); !res.Access {
					if res.Reason == MATCH_DENY_MATCH {
						return false
					}
				} else {
					allowed = true
				}
			}
		}
	}
	return allowed
}

type UserStore interface {
	GetRoles(entity EntityId) []Role
}

type MockUserStore struct{}

func (u MockUserStore) GetRoles(entity EntityId) []Role {
	tag := Tag{Id: "1", Name: "Admin"}
	policy := Policy{
		Name:        "AccessControl",
		Description: "Defines access control policies.",
		Statements: []Statement{
			NewEndpointStatement(ENV_PROD, METHOD_GET, ENDPOINT_EXAMPLE, EFFECT_ALLOW),
		},
	}
	role := Role{
		Name:        "Administrator",
		Description: "Admin role with all permissions.",
		Tags:        []Tag{tag},
		Assigments:  []EntityId{"entity1"},
		Policies:    []Policy{policy},
	}

	if entity == "entity1" {
		return []Role{role}
	}

	return []Role{}
}

func NewEndpointAuthorizationProvider(store UserStore) EndpointAuthorizationProvider {
	return EndpointAuthorizationProvider{UserStore: store}
}

type EndpointStatement struct {
	Resource EnvEndpointResource
	Effect   AllowDenyEffect
	Action   CRUDAction
}

func (e EndpointStatement) String() string {
	return fmt.Sprintf("%s:%s:%s", e.Resource, e.Effect, e.Action)
}

func NewEndpointStatement(env Env, method EndpointMethod, endpoint EndpointPath, effect AllowDeny) EndpointStatement {
	action := CRUD_READ
	if method == METHOD_POST {
		action = CRUD_CREATE
	}
	return EndpointStatement{
		Resource: NewResource(env, method, endpoint),
		Effect:   NewEffect(effect),
		Action:   NewAction(action),
	}
}

type MatchReason string

const (
	MATCH_ALLOW_MATCH     MatchReason = "ALLOW_MATCH"
	MATCH_DENY_MATCH      MatchReason = "DENY_MATCH"
	MATCH_LEAST_PRIVILEGE MatchReason = "LEAST_PRIVILEGE"
)

type EndpointStatementAccessRequestResult struct {
	Access bool
	Reason MatchReason
}

func (e EndpointStatement) Allowed(statement Statement) EndpointStatementAccessRequestResult {
	access := false
	reason := MATCH_LEAST_PRIVILEGE
	if s, ok := statement.(EndpointStatement); ok {
		match := e.Resource.Match(s.Resource) && e.Action.Match(s.Action)
		if match {
			if s.Effect.Match(NewEffect(EFFECT_ALLOW)) {
				access = true
				reason = MATCH_ALLOW_MATCH
			} else {
				return EndpointStatementAccessRequestResult{
					Access: false,
					Reason: MATCH_DENY_MATCH,
				}
			}
		}
	}
	return EndpointStatementAccessRequestResult{
		Access: access,
		Reason: reason,
	}
}

func AuthorizationMiddleware(auth EndpointAuthorizationProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entity := EntityId(r.Header.Get("X-Entity-ID"))
			path := EndpointPath(r.URL.Path)
			method := EndpointMethod(r.Method)
			statement := NewEndpointStatement(ENV_PROD, method, path, EFFECT_ALLOW)

			if !auth.IsAuthorized(entity, statement) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
