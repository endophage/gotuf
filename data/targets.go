package data

import (
	"crypto/sha256"
	"encoding/hex"
)

type Targets struct {
	Type        string      `json:"_type"`
	Version     int         `json:"version"`
	Expires     string      `json:"expires"`
	Targets     Files       `json:"targets"`
	Delegations Delegations `json:"delegations,omitempty"`
}

// GetMeta attempts to find the targets entry for the path. It
// will return nil in the case of the target not being found.
func (t Targets) GetMeta(path string) *FileMeta {
	for p, meta := range t.Targets {
		if p == path {
			return &meta
		}
	}
	return nil
}

// GetDelegations filters the roles and associated keys that may be
// the signers for the given target path. If no appropriate roles
// can be found, it will simply return nil for the return values.
// The returned slice of Role will have order maintained relative
// to the role slice on t.Delegations per TUF spec proposal on using
// order to determine priority.
func (t Targets) GetDelegations(path string) []*Role {
	roles := make([]*Role, 0)
	pathHashBytes := sha256.Sum256([]byte(path))
	pathHash := hex.EncodeToString(pathHashBytes[:])
	for _, r := range t.Delegations.Roles {
		if !r.IsValid() {
			// Role has both Paths and PathHashPrefixes.
			continue
		}
		if r.CheckPaths(path) {
			roles = append(roles, r)
			continue
		}
		if r.CheckPrefixes(pathHash) {
			roles = append(roles, r)
			continue
		}
		//keysDB.AddRole(r)
	}
	return roles
}
