/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package oauth2w_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i-core/oauth2w"
	"github.com/kylelemons/godebug/pretty"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		name       string
		ep         string
		roleFinder oauth2w.RoleFinder
		oidcStatus int
		oidcBody   []byte
	}{
		{
			name: "empty oidc endpoint",
			ep:   "",
		},
		{
			name: "empty role's finder",
			ep:   "test",
		},
		{
			name:       "invalid oidc endpoint url",
			ep:         "://test",
			roleFinder: &testRoleFinder{},
		},
		{
			name:       "oidc endpoint net error",
			ep:         "http://test",
			roleFinder: &testRoleFinder{},
		},
		{
			name:       "invalid oidc endpoint response",
			roleFinder: &testRoleFinder{},
			oidcStatus: http.StatusOK,
			oidcBody:   []byte("invalid"),
		},
		{
			name:       "oidc endpoint error response",
			roleFinder: &testRoleFinder{},
			oidcStatus: http.StatusInternalServerError,
			oidcBody:   []byte("{}"),
		},
		{
			name:       "invalid oidc configuration",
			roleFinder: &testRoleFinder{},
			oidcStatus: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			if tc.oidcStatus != 0 {
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.oidcStatus)
					if tc.oidcBody != nil {
						w.Write(tc.oidcBody)
					}
				}))
				defer srv.Close()
			}

			url := tc.ep
			if srv != nil {
				url = srv.URL
			}

			_, err := oauth2w.New(url, tc.roleFinder)
			if err == nil {
				t.Fatalf("got not one error, want error")
			}
		})
	}
}

func TestMiddleware(t *testing.T) {
	testCases := []struct {
		name       string
		roleFinder oauth2w.RoleFinder
		withLog    bool
		withDebug  bool
		oidcCnf    map[string]interface{}
		roles      []string
		token      string
		oidcStatus int
		oidcBody   []byte
		wantStatus int
		wantUser   *oauth2w.User
	}{
		{
			name:       "empty required roles",
			wantStatus: http.StatusOK,
		},
		{
			name:       "without header Authorization",
			roles:      []string{"user"},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid userinfo endpoint url",
			roles:      []string{"user"},
			token:      "foo",
			oidcCnf:    map[string]interface{}{"userinfo_endpoint": "test/userinfo"},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "invalid userinfo endpoint",
			roles:      []string{"user"},
			token:      "foo",
			oidcCnf:    map[string]interface{}{"userinfo_endpoint": "http://test/userinfo"},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "invalid access token",
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusUnauthorized,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "OIDC endpoint internal error",
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusInternalServerError,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "invalid userinfo",
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusOK,
			oidcBody:   []byte("invalid"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "userinfo without a email claim",
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusOK,
			oidcBody:   toJSON(map[string]interface{}{"roles": []interface{}{"test"}}),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "userinfo with an invalid email claim",
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusOK,
			oidcBody:   toJSON(map[string]interface{}{"email": 1, "roles": []interface{}{"test"}}),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "find roles error",
			roleFinder: &testRoleFinder{err: fmt.Errorf("find roles error")},
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusOK,
			oidcBody:   toJSON(map[string]interface{}{"email": "test@example.org", "roles": []interface{}{"test"}}),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "unauthorized",
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusOK,
			oidcBody:   toJSON(map[string]interface{}{"email": "test@example.org", "roles": []interface{}{"test"}}),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "authorized with a custom role",
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusOK,
			oidcBody:   toJSON(map[string]interface{}{"email": "test@example.org", "roles": []interface{}{"user"}}),
			wantStatus: http.StatusOK,
			wantUser:   &oauth2w.User{Email: "test@example.org", Roles: []string{"user", "_default"}},
		},
		{
			name:       "authorized with the default role",
			roles:      []string{"_default"},
			token:      "foo",
			oidcStatus: http.StatusOK,
			oidcBody:   toJSON(map[string]interface{}{"email": "test@example.org", "roles": []interface{}{"user"}}),
			wantStatus: http.StatusOK,
			wantUser:   &oauth2w.User{Email: "test@example.org", Roles: []string{"user", "_default"}},
		},
		{
			name:       "with log",
			withLog:    true,
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusOK,
			oidcBody:   []byte("invalid"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "with debug",
			withDebug:  true,
			roles:      []string{"user"},
			token:      "foo",
			oidcStatus: http.StatusOK,
			oidcBody:   toJSON(map[string]interface{}{"email": "test@example.org", "roles": []interface{}{"user"}}),
			wantStatus: http.StatusOK,
			wantUser:   &oauth2w.User{Email: "test@example.org", Roles: []string{"user", "_default"}},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/openid-configuration" {
					w.WriteHeader(http.StatusOK)

					oidcCnf := tc.oidcCnf
					if oidcCnf == nil {
						oidcCnf = map[string]interface{}{"userinfo_endpoint": srv.URL + "/userinfo"}
					}

					if err := json.NewEncoder(w).Encode(oidcCnf); err != nil {
						t.Fatalf("failed to write openid configuration")
					}
					return
				}
				w.WriteHeader(tc.oidcStatus)
				if tc.oidcBody != nil {
					if _, err := w.Write(tc.oidcBody); err != nil {
						panic("failed to write oidc body")
					}
				}
			}))
			defer srv.Close()

			roleFinder := tc.roleFinder
			if roleFinder == nil {
				roleFinder = &testRoleFinder{}
			}
			spy := &logSpy{}
			var opts []oauth2w.Option
			if tc.withLog {
				opts = append(opts, oauth2w.WithLogPrint(spy.logPrint))
			}
			if tc.withDebug {
				opts = append(opts, oauth2w.WithLogDebug(spy.logDebug))
			}
			authwFn, err := oauth2w.New(srv.URL, roleFinder, opts...)
			if err != nil {
				t.Fatalf("failed to create the middleware: %s", err)
			}
			authw := authwFn(tc.roles)

			var gotUser *oauth2w.User
			h := authw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotUser = oauth2w.FindUser(r.Context())
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://test", nil)
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			h.ServeHTTP(w, r)

			if w.Code != tc.wantStatus {
				t.Errorf("got status %d, want status %d", w.Code, tc.wantStatus)
			}
			if w.Code == http.StatusOK {
				if diff := pretty.Compare(gotUser, tc.wantUser); diff != "" {
					t.Errorf("diff: (-got + want)\n%s", diff)
				}
			} else {
				if gotUser != nil {
					t.Errorf("got user data in the request context, want no user data in the request context")
				}
			}
			if tc.withLog && !spy.logCalled {
				t.Errorf("got no one call of logPrint function, want logPrint function to be called")
			}
			if tc.withDebug && !spy.debugCalled {
				t.Errorf("got no one call of logDebug function, want logDebug function to be called")
			}
		})
	}
}

func toJSON(data interface{}) []byte {
	b, err := json.Marshal(data)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal %v to json: %s", data, err))
	}
	return b
}

type testRoleFinder struct {
	err error
}

func (f *testRoleFinder) FindRoles(claims map[string]interface{}) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	roleClaim, ok := claims["roles"]
	if !ok {
		return nil, nil
	}
	roles, ok := roleClaim.([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid role claim")
	}
	var vv []string
	for _, v := range roles {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("invalid role claim")
		}
		vv = append(vv, s)
	}
	return vv, nil
}

type logSpy struct {
	logCalled   bool
	debugCalled bool
}

func (s *logSpy) logPrint(ctx context.Context) func(string, ...interface{}) {
	return func(string, ...interface{}) {
		s.logCalled = true
	}
}

func (s *logSpy) logDebug(ctx context.Context) func(string, ...interface{}) {
	return func(string, ...interface{}) {
		s.debugCalled = true
	}
}
