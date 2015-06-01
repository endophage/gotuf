package roles

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
