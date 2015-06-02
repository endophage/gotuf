package data

import (
	"fmt"
	"strings"
)

var validRoles = map[string]string{
	"root":      "root",
	"targets":   "targets",
	"snapshot":  "snapshot",
	"timestamp": "timestamp",
}

func SetValidRoles(rs map[string]string) {
	for k, v := range rs {
		validRoles[strings.ToLower(k)] = strings.ToLower(v)
	}
}

func RoleName(role string) string {
	if r, ok := validRoles[role]; ok {
		return r
	}
	return role
}

// ValidRole only determines the name is semantically
// correct. For target delegated roles, it does NOT check
// the the appropriate parent roles exist.
func ValidRole(name string) bool {
	name = strings.ToLower(name)
	if _, ok := validRoles[name]; ok {
		return true
	}
	targetsBase := fmt.Sprintf("%s/", validRoles["targets"])
	if strings.HasPrefix(name, targetsBase) {
		return true
	}
	for _, v := range validRoles {
		if name == v {
			return true
		}
	}
	return false
}

type Role struct {
	KeyIDs           []string `json:"keyids"`
	Name             string   `json:"name"`
	Paths            []string `json:"paths"`
	PathHashPrefixes []string `json:"path_hash_prefixes"`
	Threshold        int      `json:"threshold"`
}

func (r Role) IsValid() bool {
	return !(len(r.Paths) > 0 && len(r.PathHashPrefixes) > 0)
}

func (r Role) ValidKey(id string) bool {
	for _, key := range r.KeyIDs {
		if key == id {
			return true
		}
	}
	return false
}

func (r Role) CheckPaths(path string) bool {
	for _, p := range r.Paths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (r Role) CheckPrefixes(hash string) bool {
	for _, p := range r.PathHashPrefixes {
		if strings.HasPrefix(hash, p) {
			return true
		}
	}
	return false
}
