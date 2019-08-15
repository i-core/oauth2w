/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package werther

import (
	"fmt"
)

// DefaultRoleClaim is the default name of the role claim that Werther returns.
const DefaultRoleClaim = "https://github.com/i-core/werther/claims/roles"

// ErrInvalidRoleClaim is an error that happens when a value of the role claim is invalid.
var ErrInvalidRoleClaim = fmt.Errorf("invalid role claim")

// RoleFinder is a role finder that finds user roles in the user's claims received
// from Werther (https://github.com/i-core/werther).
type RoleFinder struct {
	roleClaim, roleGroup string
}

// NewRoleFinder returns a new RoleFinder that finds user roles for the specified role's group.
func NewRoleFinder(roleGroup string) *RoleFinder {
	return &RoleFinder{roleClaim: DefaultRoleClaim, roleGroup: roleGroup}
}

// WithRoleClaim overrides the default name of the role claim.
func (f *RoleFinder) WithRoleClaim(roleClaim string) *RoleFinder {
	f.roleClaim = roleClaim
	return f
}

// FindRoles returns user roles for the configured role group.
// The method finds roles in the configured role claim.
func (f *RoleFinder) FindRoles(claims map[string]interface{}) ([]string, error) {
	allRoles, ok := claims[f.roleClaim]
	if !ok {
		return nil, nil
	}
	appsRoles, ok := allRoles.(map[string]interface{})
	if !ok {
		return nil, ErrInvalidRoleClaim
	}
	appRoles, ok := appsRoles[f.roleGroup]
	if !ok {
		return nil, nil
	}
	gotRoles, ok := appRoles.([]interface{})
	if !ok {
		return nil, ErrInvalidRoleClaim
	}
	var roles []string
	for _, v := range gotRoles {
		role, ok := v.(string)
		if !ok {
			return nil, ErrInvalidRoleClaim
		}
		roles = append(roles, role)
	}
	return roles, nil
}
