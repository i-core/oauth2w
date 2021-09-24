# oauth2w

[![GoDoc][doc-img]][doc] [![Build Status][build-img]][build] [![codecov][codecov-img]][codecov] [![Go Report Card][goreport-img]][goreport]

oauth2w provides HTTP middlewares that enables authorization via [the OpenID Connect protocol][oidc-spec-core].

## Installation

```bash
go get github.com/i-core/oauth2w
```

## How it works

1. A client sends HTTP request that contains an OpenID Connect Access Token within the header `Authorization`.
2. The authentication middleware requests user claims using the userinfo's endpoint of OpenID Connect Provider
   and put user data to the request context using the interface `oauth2w.RoleFinder`.
3. The authorization middleware requests user roles from user data in the request context.
4. The authorization middleware validates that a user has the required roles, and according to it, allows or not the HTTP request.

**Notes**. Getting user roles is out of scope the library. You must provide an implementation of `oauth2w.RoleFinder`
that receives user claims and returns the user's roles.

## Usage

### Simple

```go
package main

import (
    "fmt"
    "net/http"
    "os"

    "github.com/i-core/oauth2w"
)

const oidcEndpoint = "https://openid-connect-provider.org"

func main() {
    authenticationw, err := oauth2w.NewAuthenticationMW(oidcEndpoint, &RoleFinder{})
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    authorizationw := oauth2w.NewAuthorizationMW()

    http.HandleFunc("/profile", authenticationw(authorizationw([]string{"user"})(func(w http.ResponseWriter, r *http.Request) {
        fmt.Println("Profile page")
    })))
    http.HandleFunc("/admin", authenticationw(authorizationw([]string{"admin"})(func(w http.ResponseWriter, r *http.Request) {
        fmt.Println("Admin page")
    })))

    fmt.Println(http.ListenAndServe(":8080", nil))
}

// RoleFinder finds user roles in the user's claims.
type RoleFinder struct {}
func (f *RoleFinder) FindRoles(claims map[string]interface{}) ([]string, error) {
    roleClaim, ok := claims['roles']
    if !ok {
        return nil, nil
    }
    roles, ok := roleClaim.([]interface{})
    !ok {
        return nil, fmt.Errorf("invalid role claim \"roles\"")
    }
    var vv []string
    for _, role := range roles {
        s, ok := role.(string)
        if !ok {
            return nil, fmt.Errorf("invalid role claim \"roles\"")
        }
        vv = append(vv, s)
    }
    return vv, nil
}
```

### Logging

```go
package main

import (
    "fmt"

    "github.com/i-core/oauth2w"
)

const oidcEndpoint = "https://openid-connect-provider.org"

func main() {
    logPrintFn := func(ctx context.Context) func(string, ...interface{}) {
        return func(msg string, keysAndValues ...interface{}) {
            params = append([]interface{}{"Info:", msg}, ...keysAndValues)
            fmt.Println(params...)
        }
    }
    logDebugFn := func(ctx context.Context) func(string, ...interface{}) {
        return func(msg string, keysAndValues ...interface{}) {
            params = append([]interface{}{"Debug:", msg}, ...keysAndValues)
            fmt.Println(params...)
        }
    }
    authw, err := oauth2w.NewAuthenticationMW(oidcEndpoint, &RoleFinder{}, oauth2w.WithLogPrint(logPrintFn), oauth2w.WithLogDebug(logDebugFn))
    // ...
}
```

### Accessing user data

```go
package main

import (
    "fmt"
    "net/http"
    "os"

    "github.com/i-core/oauth2w"
)

const oidcEndpoint = "https://openid-connect-provider.org"

func main() {
    authenticationw, err := oauth2w.NewAuthenticationMW(oidcEndpoint, &RoleFinder{})
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    http.HandleFunc("/profile", authenticationw(func(w http.ResponseWriter, r *http.Request) {
        user, ok := oauth2w.FindUser(r.Context())
        fmt.Printf("User %v\n", user)
    }))

fmt.Println(http.ListenAndServe(":8080", nil))
}
```

### Usage with Ory Hydra and Werther

When you use OpenID Connect Provider [ORY Hydra][hydra] with Identity Provider [Werther][werther] you can use
an implementation of `RoleFinder` from package `github.com/i-core/oauth2w/werther`.

With the default role claim:

```go
package main

import (
    "github.com/i-core/oauth2w"
    "github.com/i-core/oauth2w/werther"
)

const (
    oidcEndpoint = "https://openid-connect-provider.org"
    roleGroupID  = "myapp"
)

func main() {
    authw, err := oauth2w.New(oidcEndpoint, werther.NewRoleFinder(roleGroupID))
    // ...
}
```

With a custom name of the role claim:

```go
package main

import (
    "github.com/i-core/oauth2w"
    "github.com/i-core/oauth2w/werther"
)

const (
    oidcEndpoint = "https://openid-connect-provider.org"
    roleClaim    = "http://my-company.org/claims/roles"
    roleGroupID  = "myapp"
)

func main() {
    authw, err := oauth2w.NewAuthenticationMW(oidcEndpoint, werther.NewRoleFinder(roleGroupID).WithRoleClaim(roleClaim))
    // ...
}
```

## Contributing

Thanks for your interest in contributing to this project.
Get started with our [Contributing Guide][contrib].

## License

The code in this project is licensed under [MIT license][license].

[doc-img]: https://godoc.org/github.com/i-core/oauth2w?status.svg
[doc]: https://godoc.org/github.com/i-core/oauth2w
[build-img]: https://travis-ci.com/i-core/oauth2w.svg?branch=master
[build]: https://travis-ci.com/i-core/oauth2w
[codecov-img]: https://codecov.io/gh/i-core/oauth2w/branch/master/graph/badge.svg
[codecov]: https://codecov.io/gh/i-core/oauth2w
[goreport-img]: https://goreportcard.com/badge/github.com/i-core/oauth2w
[goreport]: https://goreportcard.com/report/github.com/i-core/oauth2w
[contrib]: https://github.com/i-core/.github/blob/master/CONTRIBUTING.md
[license]: LICENSE
[oidc-spec-core]: https://openid.net/specs/openid-connect-core-1_0.html
[hydra]: https://github.com/ory/hydra
[werther]: https://github.com/i-core/werther
