/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package oauth2w // import "github.com/i-core/oauth2w"

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type ctxkey string

const (
	errMsgInternalServerError = "internal server error"
	errMsgPermissionDenied    = "permission denied"

	claimEmail = "email"

	ctxkeyUser ctxkey = "github.com/i-core/oauth2w/user"
)

// User contains data of an authenticated user.
type User struct {
	Email string
	Roles []string
}

// LogFn is a function that provides a logging function for HTTP request.
type LogFn func(context.Context) func(string, ...interface{})

var dummyLogFn = func(context.Context) func(string, ...interface{}) { return func(string, ...interface{}) {} }

// RoleFinder is an interface to find user roles using the user's claims.
type RoleFinder interface {
	FindRoles(claims map[string]interface{}) ([]string, error)
}

type config struct {
	logPrintFn, logDebugFn LogFn
	roleFinder             RoleFinder
}

// Option describes a function for the middleware's configuration.
type Option func(*config)

// WithLogPrint returns an option that configures an info logger.
func WithLogPrint(logFn LogFn) Option {
	return func(cnf *config) {
		cnf.logPrintFn = logFn
	}
}

// WithLogDebug returns an option that configures a debug logger.
func WithLogDebug(logFn LogFn) Option {
	return func(cnf *config) {
		cnf.logDebugFn = logFn
	}
}

// NewAuthenticationMW returns a new instance of the authentication middleware.
//
// To authenticated a user the middleware requests user claims from an OpenID Connect Provider.
// If the OpenID Connect Provider responds with claims the user is considered authenticated.
// If the OpenID Connect Provider responds with 401 error the user is considered unauthenticated.
//
// If user is authenticated the middleware put to the request context user data (email and roles).
// To get user roles the middleware transforms user claims to roles using the interface RoleFinder.
//
// endpoint is an endpoint of an OpenID Connect Provider.
func NewAuthenticationMW(endpoint string, roleFinder RoleFinder, opts ...Option) (func(http.Handler) http.Handler, error) {
	httpClient := &http.Client{}
	if endpoint == "" {
		return nil, fmt.Errorf("oauth2w: OIDC's endpoint is empty")
	}
	if roleFinder == nil {
		return nil, fmt.Errorf("oauth2w: role finder is not defined")
	}

	cnf := &config{logPrintFn: dummyLogFn, logDebugFn: dummyLogFn, roleFinder: roleFinder}
	for _, opt := range opts {
		opt(cnf)
	}

	req, err := http.NewRequest(http.MethodGet, endpoint+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, fmt.Errorf("oauth2w: OIDC's configuration request: %s", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2w: send a request for getting OIDC's configuration: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var msg []byte
		if msg, err = ioutil.ReadAll(resp.Body); err != nil {
			return nil, fmt.Errorf("oauth2w: get OIDC's configuration: url=%q, status=%d: %s", req.URL, resp.StatusCode, err)
		}
		return nil, fmt.Errorf("oauth2w: get OIDC's configuration: url=%q, status=%d: %s", req.URL, resp.StatusCode, string(msg))
	}

	type oidcConfig struct {
		UserinfoEP string `json:"userinfo_endpoint"`
	}
	var oidcCnf oidcConfig
	if resp.Body != http.NoBody {
		if err = json.NewDecoder(resp.Body).Decode(&oidcCnf); err != nil {
			return nil, fmt.Errorf("oauth2w: parse OIDC's configuration: %s", err)
		}
	}

	if oidcCnf.UserinfoEP == "" {
		return nil, fmt.Errorf("oauth2w: OIDC's configuration: userinfo's endpoint is empty")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logPrint, logDebug := cnf.logPrintFn(r.Context()), cnf.logDebugFn(r.Context())
			token := r.Header.Get("Authorization")
			if token == "" {
				httpError(w, http.StatusUnauthorized, "no OAuth2 access token")
				logDebug("Authorization is unsuccessful because no OAuth2 access token")
				return
			}

			req, err := http.NewRequest(http.MethodPost, oidcCnf.UserinfoEP, nil)
			if err != nil {
				httpError(w, http.StatusInternalServerError, errMsgInternalServerError)
				logPrint("Failed to create a request to get a user's info", "userinfoEndpoint", req.URL.String(), "error", err)
				return
			}

			req.Header.Set("Authorization", token)
			resp, err := httpClient.Do(req)
			if err != nil {
				httpError(w, http.StatusInternalServerError, errMsgInternalServerError)
				logPrint("Failed to send a request to get a user's info", "userinfoEndpoint", req.URL.String(), "error", err)
				return
			}

			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				if resp.StatusCode == http.StatusUnauthorized {
					var msg []byte
					if resp.Body != http.NoBody {
						if msg, err = ioutil.ReadAll(resp.Body); err != nil {
							httpError(w, http.StatusInternalServerError, errMsgInternalServerError)
							logPrint("Failed to read a user's info response", "userinfoEndpoint", req.URL.String(), "status", resp.StatusCode, "error", err)
							return
						}
					}
					httpError(w, http.StatusUnauthorized, "the access token is invalid")
					logDebug("Authorization is unsuccessful because of an invalid OAuth2 access token", "userinfoEndpoint", req.URL.String(), "message", string(msg))
					return
				}
				httpError(w, http.StatusInternalServerError, errMsgInternalServerError)
				logPrint("Failed to get a user's info", "userinfoEndpoint", req.URL.String(), "status", resp.StatusCode, "error", err)
				return
			}

			claims := make(map[string]interface{})
			if resp.Body != http.NoBody {
				if err = json.NewDecoder(resp.Body).Decode(&claims); err != nil {
					httpError(w, http.StatusInternalServerError, errMsgInternalServerError)
					logPrint("Failed to parse a user's info", "userinfoEndpoint", req.URL.String(), "error", err)
					return
				}
			}

			emailClaim, ok := claims[claimEmail]
			if !ok {
				httpError(w, http.StatusInternalServerError, "")
				logDebug("Authorization failed while finding email", "claims", claims)
				return
			}
			email, ok := emailClaim.(string)
			if !ok || email == "" {
				httpError(w, http.StatusInternalServerError, "")
				logDebug("Authorization failed: invalid email", "claims", claims)
				return
			}
			roles, err := cnf.roleFinder.FindRoles(claims)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "")
				logDebug("Authorization failed while finding roles", "claims", claims, "rolesClaim", err)
				return
			}

			logDebug("Authorization is successful", "token", token)
			next.ServeHTTP(w, r.WithContext(contextWithUser(r.Context(), &User{Email: email, Roles: roles})))
		})
	}, nil
}

// NewAuthorizationMW returns a new instance of the authorization middleware.
//
// To authorize HTTP request the middleware validates that the user is authenticated by the authentication middleware
// and has all required roles.
// When there is no required roles the middleware authorizes all HTTP requests.
func NewAuthorizationMW(opts ...Option) func([]string) func(http.Handler) http.Handler {
	cnf := &config{logPrintFn: dummyLogFn, logDebugFn: dummyLogFn}
	for _, opt := range opts {
		opt(cnf)
	}

	return func(wantRoles []string) func(http.Handler) http.Handler {
		if len(wantRoles) == 0 {
			return func(next http.Handler) http.Handler { return next }
		}

		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logDebug := cnf.logDebugFn(r.Context())

				user, ok := FindUser(r.Context())
				if !ok {
					httpError(w, http.StatusForbidden, "user is not authenticated")
					logDebug("Authorization is unsuccessful because there is no an authenticated user")
					return
				}

				var found bool
				for _, wr := range wantRoles {
					for _, gr := range user.Roles {
						if wr == gr {
							found = true
							break
						}
					}
				}
				if !found {
					httpError(w, http.StatusForbidden, errMsgPermissionDenied)
					logDebug("Authorization failed because the user has no required roles", "requiredRoles", wantRoles)
					return
				}

				next.ServeHTTP(w, r)
			})
		}
	}
}

// httpError writes an error to a response in a standard form.
func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{"message": msg}); err != nil {
		panic(err)
	}
}

// FindUser returs data of an uthenticated user from the request context.
func FindUser(ctx context.Context) (*User, bool) {
	v := ctx.Value(ctxkeyUser)
	user, ok := v.(*User)
	if !ok || v == nil {
		return nil, false
	}
	return user, true
}

func contextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, ctxkeyUser, user)
}
