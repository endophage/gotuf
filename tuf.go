package tuf

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/endophage/gotuf/data"
	"github.com/endophage/gotuf/errors"
	"github.com/endophage/gotuf/keys"
	"github.com/endophage/gotuf/signed"
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
	signer    *signed.Signer
}

func NewTufRepo(keysDB *keys.KeyDB, signer *signed.Signer) *TufRepo {
	repo := &TufRepo{
		Targets: make(map[string]*data.SignedTargets),
		keysDB:  keysDB,
		signer:  signer,
	}
	return repo
}

func (tr *TufRepo) AddKeys(role string, keys ...data.Key) error {
	return nil
}

func (tr *TufRepo) RemoveKeys(role string, keyID ...string) error {
	return nil
}

func (tr *TufRepo) CreateDelegation(name string, keys []data.Key, role *data.Role) error {
	return nil
}

// InitRepo creates the base files for a repo. It inspects data.ValidRoles and
// data.ValidTypes to determine what the role names and filename should be. It
// also relies on the keysDB having already been populated with the keys and
// roles.
func (tr *TufRepo) InitRepo(consistent bool) error {
	rootRoles := make(map[string]*data.RootRole)
	rootKeys := make(map[string]*data.TUFKey)
	for _, r := range data.ValidRoles {
		role := tr.keysDB.GetRole(r)
		if role == nil {
			return errors.ErrInvalidRole{}
		}
		rootRoles[r] = &role.RootRole
		for _, kid := range role.KeyIDs {
			// don't need to check if GetKey returns nil, Key presence was
			// checked by KeyDB when role was added.
			key := tr.keysDB.GetKey(kid)
			// Create new key object to doubly ensure private key is excluded
			k := data.NewTUFKey(key.Cipher(), key.Public(), "")
			rootKeys[kid] = k
		}
	}
	root, err := data.NewRoot(rootKeys, rootRoles, consistent)
	if err != nil {
		return err
	}
	tr.Root = root

	targets := data.NewTargets()
	tr.Targets[data.ValidRoles["targets"]] = targets

	signedRoot, err := tr.SignRoot(data.DefaultExpires("root"))
	if err != nil {
		return err
	}
	signedTargets, err := tr.SignTargets("targets", data.DefaultExpires("targets"))
	if err != nil {
		return err
	}
	snapshot, err := data.NewSnapshot(signedRoot, signedTargets)
	if err != nil {
		return err
	}
	tr.Snapshot = snapshot

	signedSnapshot, err := tr.SignSnapshot(data.DefaultExpires("snapshot"))
	if err != nil {
		return err
	}
	timestamp, err := data.NewTimestamp(signedSnapshot)
	if err != nil {
		return err
	}

	tr.Timestamp = timestamp
	return nil
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
		roleName = strings.TrimSuffix(roleName, ".txt")
		rol, err := data.NewRole(
			roleName,
			role.Threshold,
			role.KeyIDs,
			nil,
			nil,
		)
		if err != nil {
			return err
		}
		err = tr.keysDB.AddRole(rol)
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

// AddTargetsToRole will attempt to add the given targets specifically to
// the directed role. If the user does not have the signing keys for the role
// the function will return an error and the full slice of targets.
func (tr *TufRepo) AddTargets(role string, targets *data.Files) (*data.Files, error) {
	return nil, nil
}

func (tr *TufRepo) SignRoot(expires time.Time) (*data.Signed, error) {
	signed, err := tr.Root.ToSigned()
	if err != nil {
		return nil, err
	}
	root := tr.keysDB.GetRole(data.ValidRoles["root"])
	signed, err = tr.sign(signed, *root)
	if err != nil {
		return nil, err
	}
	tr.Root.Signatures = signed.Signatures
	return signed, nil
}

func (tr *TufRepo) SignTargets(role string, expires time.Time) (*data.Signed, error) {
	signed, err := tr.Targets[role].ToSigned()
	if err != nil {
		return nil, err
	}
	targets := tr.keysDB.GetRole(role)
	signed, err = tr.sign(signed, *targets)
	if err != nil {
		return nil, err
	}
	tr.Targets[role].Signatures = signed.Signatures
	return signed, nil
}

func (tr *TufRepo) SignSnapshot(expires time.Time) (*data.Signed, error) {
	signed, err := tr.Snapshot.ToSigned()
	if err != nil {
		return nil, err
	}
	snapshot := tr.keysDB.GetRole(data.ValidRoles["snapshot"])
	signed, err = tr.sign(signed, *snapshot)
	if err != nil {
		return nil, err
	}
	tr.Snapshot.Signatures = signed.Signatures
	return signed, nil
}

func (tr *TufRepo) SignTimestamp(expires time.Time) (*data.Signed, error) {
	signed, err := tr.Timestamp.ToSigned()
	if err != nil {
		return nil, err
	}
	timestamp := tr.keysDB.GetRole(data.ValidRoles["timestamp"])
	signed, err = tr.sign(signed, *timestamp)
	if err != nil {
		return nil, err
	}
	tr.Timestamp.Signatures = signed.Signatures
	return signed, nil
}

func (tr TufRepo) sign(signed *data.Signed, role data.Role) (*data.Signed, error) {
	ks := make([]*data.PublicKey, 0, len(role.KeyIDs))
	for _, kid := range role.KeyIDs {
		k := tr.keysDB.GetKey(kid)
		if k == nil {
			continue
		}
		ks = append(ks, k)
	}
	if len(ks) < 1 {
		return nil, keys.ErrInvalidKey
	}
	err := tr.signer.Sign(signed, ks...)
	if err != nil {
		return nil, err
	}
	return signed, nil
}
