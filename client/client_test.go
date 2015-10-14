package client

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	tuf "github.com/endophage/gotuf"
	"github.com/stretchr/testify/assert"

	"github.com/endophage/gotuf/data"
	"github.com/endophage/gotuf/keys"
	"github.com/endophage/gotuf/signed"
	"github.com/endophage/gotuf/store"
)

func TestRotation(t *testing.T) {
	kdb := keys.NewDB()
	signer := signed.NewEd25519()
	repo := tuf.NewTufRepo(kdb, signer)
	remote := store.NewMemoryStore(nil, nil)
	cache := store.NewMemoryStore(nil, nil)

	// Generate initial root key and role and add to key DB
	rootKey, err := signer.Create("root", data.ED25519Key)
	assert.NoError(t, err, "Error creating root key")
	rootRole, err := data.NewRole("root", 1, []string{rootKey.ID()}, nil, nil)
	assert.NoError(t, err, "Error creating root role")

	kdb.AddKey(rootKey)
	err = kdb.AddRole(rootRole)
	assert.NoError(t, err, "Error adding root role to db")

	// Generate new key and role. These will appear in the root.json
	// but will not be added to the keyDB.
	replacementKey, err := signer.Create("root", data.ED25519Key)
	assert.NoError(t, err, "Error creating replacement root key")
	replacementRole, err := data.NewRole("root", 1, []string{replacementKey.ID()}, nil, nil)
	assert.NoError(t, err, "Error creating replacement root role")

	// Generate a new root with the replacement key and role
	testRoot, err := data.NewRoot(
		map[string]data.PublicKey{replacementKey.ID(): replacementKey},
		map[string]*data.RootRole{"root": &replacementRole.RootRole},
		false,
	)
	assert.NoError(t, err, "Failed to create new root")

	// Sign testRoot with both old and new keys
	signedRoot, err := testRoot.ToSigned()
	err = signed.Sign(signer, signedRoot, rootKey, replacementKey)
	assert.NoError(t, err, "Failed to sign root")
	var origKeySig bool
	var replKeySig bool
	for _, sig := range signedRoot.Signatures {
		if sig.KeyID == rootKey.ID() {
			origKeySig = true
		} else if sig.KeyID == replacementKey.ID() {
			replKeySig = true
		}
	}
	assert.True(t, origKeySig, "Original root key signature not present")
	assert.True(t, replKeySig, "Replacement root key signature not present")

	client := NewClient(repo, remote, kdb, cache)

	err = client.verifyRoot("root", signedRoot, 0)
	assert.NoError(t, err, "Failed to verify key rotated root")
}

func TestRotationNewSigMissing(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	kdb := keys.NewDB()
	signer := signed.NewEd25519()
	repo := tuf.NewTufRepo(kdb, signer)
	remote := store.NewMemoryStore(nil, nil)
	cache := store.NewMemoryStore(nil, nil)

	// Generate initial root key and role and add to key DB
	rootKey, err := signer.Create("root", data.ED25519Key)
	assert.NoError(t, err, "Error creating root key")
	rootRole, err := data.NewRole("root", 1, []string{rootKey.ID()}, nil, nil)
	assert.NoError(t, err, "Error creating root role")

	kdb.AddKey(rootKey)
	err = kdb.AddRole(rootRole)
	assert.NoError(t, err, "Error adding root role to db")

	// Generate new key and role. These will appear in the root.json
	// but will not be added to the keyDB.
	replacementKey, err := signer.Create("root", data.ED25519Key)
	assert.NoError(t, err, "Error creating replacement root key")
	replacementRole, err := data.NewRole("root", 1, []string{replacementKey.ID()}, nil, nil)
	assert.NoError(t, err, "Error creating replacement root role")

	assert.NotEqual(t, rootKey.ID(), replacementKey.ID(), "Key IDs are the same")

	// Generate a new root with the replacement key and role
	testRoot, err := data.NewRoot(
		map[string]data.PublicKey{replacementKey.ID(): replacementKey},
		map[string]*data.RootRole{"root": &replacementRole.RootRole},
		false,
	)
	assert.NoError(t, err, "Failed to create new root")

	_, ok := testRoot.Signed.Keys[rootKey.ID()]
	assert.False(t, ok, "Old root key appeared in test root")

	// Sign testRoot with both old and new keys
	signedRoot, err := testRoot.ToSigned()
	err = signed.Sign(signer, signedRoot, rootKey)
	assert.NoError(t, err, "Failed to sign root")
	var origKeySig bool
	var replKeySig bool
	for _, sig := range signedRoot.Signatures {
		if sig.KeyID == rootKey.ID() {
			origKeySig = true
		} else if sig.KeyID == replacementKey.ID() {
			replKeySig = true
		}
	}
	assert.True(t, origKeySig, "Original root key signature not present")
	assert.False(t, replKeySig, "Replacement root key signature was present and shouldn't be")

	client := NewClient(repo, remote, kdb, cache)

	err = client.verifyRoot("root", signedRoot, 0)
	assert.Error(t, err, "Should have errored on verify as replacement signature was missing.")

}

func TestRotationOldSigMissing(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	kdb := keys.NewDB()
	signer := signed.NewEd25519()
	repo := tuf.NewTufRepo(kdb, signer)
	remote := store.NewMemoryStore(nil, nil)
	cache := store.NewMemoryStore(nil, nil)

	// Generate initial root key and role and add to key DB
	rootKey, err := signer.Create("root", data.ED25519Key)
	assert.NoError(t, err, "Error creating root key")
	rootRole, err := data.NewRole("root", 1, []string{rootKey.ID()}, nil, nil)
	assert.NoError(t, err, "Error creating root role")

	kdb.AddKey(rootKey)
	err = kdb.AddRole(rootRole)
	assert.NoError(t, err, "Error adding root role to db")

	// Generate new key and role. These will appear in the root.json
	// but will not be added to the keyDB.
	replacementKey, err := signer.Create("root", data.ED25519Key)
	assert.NoError(t, err, "Error creating replacement root key")
	replacementRole, err := data.NewRole("root", 1, []string{replacementKey.ID()}, nil, nil)
	assert.NoError(t, err, "Error creating replacement root role")

	assert.NotEqual(t, rootKey.ID(), replacementKey.ID(), "Key IDs are the same")

	// Generate a new root with the replacement key and role
	testRoot, err := data.NewRoot(
		map[string]data.PublicKey{replacementKey.ID(): replacementKey},
		map[string]*data.RootRole{"root": &replacementRole.RootRole},
		false,
	)
	assert.NoError(t, err, "Failed to create new root")

	_, ok := testRoot.Signed.Keys[rootKey.ID()]
	assert.False(t, ok, "Old root key appeared in test root")

	// Sign testRoot with both old and new keys
	signedRoot, err := testRoot.ToSigned()
	err = signed.Sign(signer, signedRoot, replacementKey)
	assert.NoError(t, err, "Failed to sign root")
	var origKeySig bool
	var replKeySig bool
	for _, sig := range signedRoot.Signatures {
		if sig.KeyID == rootKey.ID() {
			origKeySig = true
		} else if sig.KeyID == replacementKey.ID() {
			replKeySig = true
		}
	}
	assert.False(t, origKeySig, "Original root key signature was present and shouldn't be")
	assert.True(t, replKeySig, "Replacement root key signature was not present")

	client := NewClient(repo, remote, kdb, cache)

	err = client.verifyRoot("root", signedRoot, 0)
	assert.Error(t, err, "Should have errored on verify as replacement signature was missing.")

}

func TestCheckRootExpired(t *testing.T) {
	repo := tuf.NewTufRepo(nil, nil)
	storage := store.NewMemoryStore(nil, nil)
	client := NewClient(repo, storage, nil, storage)

	root := &data.SignedRoot{}
	root.Signed.Expires = time.Now().AddDate(-1, 0, 0)

	signedRoot, err := root.ToSigned()
	assert.NoError(t, err)
	rootJSON, err := json.Marshal(signedRoot)
	assert.NoError(t, err)

	rootHash := sha256.Sum256(rootJSON)

	testSnap := &data.SignedSnapshot{
		Signed: data.Snapshot{
			Meta: map[string]data.FileMeta{
				"root": {
					Length: int64(len(rootJSON)),
					Hashes: map[string][]byte{
						"sha256": rootHash[:],
					},
				},
			},
		},
	}
	repo.SetRoot(root)
	repo.SetSnapshot(testSnap)

	storage.SetMeta("root", rootJSON)

	err = client.checkRoot()
	assert.Error(t, err)
	assert.IsType(t, tuf.ErrLocalRootExpired{}, err)
}

func TestChecksumMismatch(t *testing.T) {
	repo := tuf.NewTufRepo(nil, nil)
	localStorage := store.NewMemoryStore(nil, nil)
	remoteStorage := store.NewMemoryStore(nil, nil)
	client := NewClient(repo, remoteStorage, nil, localStorage)

	sampleTargets := data.NewTargets()
	orig, err := json.Marshal(sampleTargets)
	origSha256 := sha256.Sum256(orig)
	orig[0] = '}' // corrupt data, should be a {
	assert.NoError(t, err)

	remoteStorage.SetMeta("targets", orig)

	_, err = client.downloadSigned("targets", int64(len(orig)), origSha256[:])
	assert.IsType(t, ErrChecksumMismatch{}, err)
}

func TestChecksumMatch(t *testing.T) {
	repo := tuf.NewTufRepo(nil, nil)
	localStorage := store.NewMemoryStore(nil, nil)
	remoteStorage := store.NewMemoryStore(nil, nil)
	client := NewClient(repo, remoteStorage, nil, localStorage)

	sampleTargets := data.NewTargets()
	orig, err := json.Marshal(sampleTargets)
	origSha256 := sha256.Sum256(orig)
	assert.NoError(t, err)

	remoteStorage.SetMeta("targets", orig)

	_, err = client.downloadSigned("targets", int64(len(orig)), origSha256[:])
	assert.NoError(t, err)
}

func TestDownloadTargetsHappy(t *testing.T) {
	kdb := keys.NewDB()
	cs := signed.NewEd25519()
	repo := tuf.NewTufRepo(kdb, cs)
	localStorage := store.NewMemoryStore(nil, nil)
	remoteStorage := store.NewMemoryStore(nil, nil)
	client := NewClient(repo, remoteStorage, kdb, localStorage)

	// set up targets key and role
	targetsKey, err := cs.Create("targets", data.ED25519Key)
	assert.NoError(t, err)
	targetsRole, err := data.NewRole("targets", 1, []string{targetsKey.ID()}, nil, nil)
	assert.NoError(t, err)
	kdb.AddKey(targetsKey)
	kdb.AddRole(targetsRole)

	// create and "upload" sample targets
	sampleTargets := data.NewTargets()
	repo.Targets["targets"] = sampleTargets
	signedOrig, err := repo.SignTargets("targets", data.DefaultExpires("targets"), nil)
	assert.NoError(t, err)
	orig, err := json.Marshal(signedOrig)
	assert.NoError(t, err)
	origSha256 := sha256.Sum256(orig)
	err = remoteStorage.SetMeta("targets", orig)
	assert.NoError(t, err)

	// create local snapshot with targets file
	snap := data.SignedSnapshot{
		Signed: data.Snapshot{
			Meta: data.Files{
				"targets": data.FileMeta{
					Length: int64(len(orig)),
					Hashes: data.Hashes{
						"sha256": origSha256[:],
					},
				},
			},
		},
	}

	// create local root to set ConsistentSnapshot field
	root := data.SignedRoot{
		Signed: data.Root{
			ConsistentSnapshot: false,
		},
	}

	repo.Root = &root
	repo.Snapshot = &snap

	err = client.downloadTargets("targets")
	assert.NoError(t, err)
}

func TestDownloadTargetChecksumMismatch(t *testing.T) {
	kdb := keys.NewDB()
	cs := signed.NewEd25519()
	repo := tuf.NewTufRepo(kdb, cs)
	localStorage := store.NewMemoryStore(nil, nil)
	remoteStorage := store.NewMemoryStore(nil, nil)
	client := NewClient(repo, remoteStorage, kdb, localStorage)

	// set up targets key and role
	targetsKey, err := cs.Create("targets", data.ED25519Key)
	assert.NoError(t, err)
	targetsRole, err := data.NewRole("targets", 1, []string{targetsKey.ID()}, nil, nil)
	assert.NoError(t, err)
	kdb.AddKey(targetsKey)
	kdb.AddRole(targetsRole)

	// create and "upload" sample targets
	sampleTargets := data.NewTargets()
	repo.Targets["targets"] = sampleTargets
	signedOrig, err := repo.SignTargets("targets", data.DefaultExpires("targets"), nil)
	assert.NoError(t, err)
	orig, err := json.Marshal(signedOrig)
	assert.NoError(t, err)
	origSha256 := sha256.Sum256(orig)
	orig[0] = '}' // corrupt data, should be a {
	err = remoteStorage.SetMeta("targets", orig)
	assert.NoError(t, err)

	// create local snapshot with targets file
	snap := data.SignedSnapshot{
		Signed: data.Snapshot{
			Meta: data.Files{
				"targets": data.FileMeta{
					Length: int64(len(orig)),
					Hashes: data.Hashes{
						"sha256": origSha256[:],
					},
				},
			},
		},
	}

	// create local root to set ConsistentSnapshot field
	root := data.SignedRoot{
		Signed: data.Root{
			ConsistentSnapshot: false,
		},
	}

	repo.Root = &root
	repo.Snapshot = &snap

	err = client.downloadTargets("targets")
	assert.IsType(t, ErrChecksumMismatch{}, err)
}
