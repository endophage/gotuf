package tuf

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/endophage/gotuf/data"
	"github.com/endophage/gotuf/keys"
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
	Root      *data.SignedRoot
	Targets   map[string]*data.SignedTargets
	Snapshot  *data.SignedSnapshot
	Timestamp *data.SignedTimestamp
	keysDB    *keys.KeyDB
}

func NewTufRepo(keysDB *keys.KeyDB) *TufRepo {
	repo := &TufRepo{
		Targets: make(map[string]*data.SignedTargets),
		keysDB:  keysDB,
	}
	return repo
}

func (tr *TufRepo) SetRoot(s *data.Signed) error {
	r, err := data.RootFromSigned(s)
	if err != nil {
		return err
	}
	for kid, key := range r.Signed.Keys {
		tr.keysDB.AddKey(&data.PublicKey{TUFKey: *key})
		logrus.Debug("Given Key ID:", kid, "\nGenerated Key ID:", key.ID())
	}
	for roleName, role := range r.Signed.Roles {
		role.Name = strings.TrimSuffix(roleName, ".txt")
		err := tr.keysDB.AddRole(role)
		if err != nil {
			return err
		}
	}
	tr.Root = r
	return nil
}

func (tr *TufRepo) SetTimestamp(s *data.Signed) error {
	ts, err := data.TimestampFromSigned(s)
	if err != nil {
		return err
	}
	tr.Timestamp = ts
	return nil
}

func (tr *TufRepo) SetSnapshot(s *data.Signed) error {
	snap, err := data.SnapshotFromSigned(s)
	if err != nil {
		return err
	}

	tr.Snapshot = snap
	return nil
}

func (tr *TufRepo) SetTargets(role string, s *data.Signed) error {
	t, err := data.TargetsFromSigned(s)
	if err != nil {
		return err
	}
	for _, k := range t.Signed.Delegations.Keys {
		tr.keysDB.AddKey(&data.PublicKey{TUFKey: *k})
	}
	for _, r := range t.Signed.Delegations.Roles {
		tr.keysDB.AddRole(r)
	}
	tr.Targets[role] = t
	return nil
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
		if m, ok := t.Signed.Targets[path]; ok {
			return &m
		}
		// Depth first search of delegations:
		for _, r := range t.Signed.Delegations.Roles {
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

// AddTargets takes any number of FileMeta objects and adds them to the
// appropriate delegated targets files based on the keys the current
// user has available for signing.
// AddTargets may select any role that is both valid for the target and
// the current user has signing keys for. If an error occurs the returned
// data.Files will contain any targets that could not be added.
func (tr *TufRepo) AddTargets(targets *data.Files) (*data.Files, error) {
	return nil, nil
}

// AddTargetsToRole will attempt to add the given targets specifically to
// the directed role. If the user does not have the signing keys for the role
// the function will return an error and the full slice of targets.
func (tr *TufRepo) AddTargetsToRole(role string, targets *data.Files) (*data.Files, error) {
	return nil, nil
}

func (tr TufRepo) SignRoot(expires time.Time) (*data.Signed, error) {
	return nil, nil
}

func (tr TufRepo) SignTargets(role string, expires time.Time) (*data.Signed, error) {
	return nil, nil
}

func (tr TufRepo) SignSnapshot(expires time.Time) (*data.Signed, error) {
	return nil, nil
}

func (tr TufRepo) SignTimestamp(expires time.Time) (*data.Signed, error) {
	return nil, nil
}
