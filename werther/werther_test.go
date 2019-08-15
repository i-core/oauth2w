/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package werther_test

import (
	"reflect"
	"testing"

	"github.com/i-core/oauth2w/werther"
)

func TestRoleFinder(t *testing.T) {
	testCases := []struct {
		name        string
		roleGroupID string
		roleClaim   string
		claims      map[string]interface{}
		want        []string
		wantErr     error
	}{
		{
			name:        "empty role claim",
			roleGroupID: "test",
			claims:      make(map[string]interface{}),
		},
		{
			name:        "invalid role claim",
			roleGroupID: "test",
			claims: map[string]interface{}{
				werther.DefaultRoleClaim: "invalid",
			},
			wantErr: werther.ErrInvalidRoleClaim,
		},
		{
			name:        "empty role group",
			roleGroupID: "test",
			claims: map[string]interface{}{
				werther.DefaultRoleClaim: map[string]interface{}{},
			},
		},
		{
			name:        "invalid role group",
			roleGroupID: "test",
			claims: map[string]interface{}{
				werther.DefaultRoleClaim: map[string]interface{}{
					"test": "invalid",
				},
			},
			wantErr: werther.ErrInvalidRoleClaim,
		},
		{
			name:        "invalid role",
			roleGroupID: "test",
			claims: map[string]interface{}{
				werther.DefaultRoleClaim: map[string]interface{}{
					"test": []interface{}{1},
				},
			},
			wantErr: werther.ErrInvalidRoleClaim,
		},
		{
			name:        "default role claim",
			roleGroupID: "test1",
			claims: map[string]interface{}{
				werther.DefaultRoleClaim: map[string]interface{}{
					"test1": []interface{}{"role1"},
					"test2": []interface{}{"role2"},
				},
			},
			want: []string{"role1"},
		},
		{
			name:        "custom role claim",
			roleClaim:   "roles",
			roleGroupID: "test1",
			claims: map[string]interface{}{
				"roles": map[string]interface{}{
					"test1": []interface{}{"role1"},
					"test2": []interface{}{"role2"},
				},
			},
			want: []string{"role1"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			finder := werther.NewRoleFinder(tc.roleGroupID)
			if tc.roleClaim != "" {
				finder.WithRoleClaim(tc.roleClaim)
			}

			got, err := finder.FindRoles(tc.claims)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("got no errors, want error %q", tc.wantErr)
				}
				if err != tc.wantErr {
					t.Fatalf("got error %q, want error %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("got error %q, want no errors", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
