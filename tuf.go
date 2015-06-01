package tuf

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/Sirupsen/logrus"
	"github.com/endophage/go-tuf/data"
)

type ErrSigVerifyFail struct{}

func (e ErrSigVerifyFail) Error() string {
	return "Error: Signature verification failed"
}

type ErrMetaExpired struct{}

func (e ErrMetaExpired) Error() string {
	return "Error: Metadata has expired"
}

type ErrLocalRootExpired struct{}

func (e ErrLocalRootExpired) Error() string {
	return "Error: Local Root Has Expired"
}

// TufRepo is an in memory representation of the Signed section of all
// the TUF files.
type TufRepo struct {
	Root      *data.Root
	Targets   map[string]*data.Targets
	Snapshot  *data.Snapshot
	Timestamp *data.Timestamp
}

func (tr *TufRepo) SetRoot(r *data.Root) {
	tr.Root = r
}

func (tr *TufRepo) SetTimestamp(ts *data.Timestamp) {
	tr.Timestamp = ts
}

func (tr *TufRepo) SetSnapshot(sn *data.Snapshot) {
	tr.Snapshot = sn
}

func (tr *TufRepo) SetTargets(role string, t *data.Targets) {
	tr.Targets[role] = t
}

func (tr *TufRepo) WalkTargets(role, path string) *data.FileMeta {
	pathDigest := sha256.Sum256([]byte(path))
	pathHex := hex.EncodeToString(pathDigest[:])
	logrus.Debug("Path: ", path, "\nPath SHA256 Hex: ", pathHex)
	var walkTargets func(string) *data.FileMeta
	walkTargets = func(role string) *data.FileMeta {
		t, ok := tr.Targets[role]
		if !ok {
			// role not found
			return nil
		}
		if m, ok := t.Targets[path]; ok {
			return &m
		}
		// Depth first search of delegations:
		for _, r := range t.Delegations.Roles {
			if r.CheckPrefixes(pathHex) || r.CheckPaths(path) {
				logrus.Debug("Found delegation ", r.Name, " for path ", path)
				if m := walkTargets(r.Name); m != nil {
					return m
				}
			}
		}
		return nil
	}

	return walkTargets(role)
}

func (tr TufRepo) FindTarget(path string) *data.FileMeta {
	return tr.WalkTargets("targets", path)
}
