package tuf

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/endophage/gotuf/data"
	"github.com/endophage/gotuf/keys"
	"github.com/endophage/gotuf/signed"
)

func TestInitRepo(t *testing.T) {
	ed25519 := signed.NewEd25519()
	signer := signed.NewSigner(ed25519)

	rootKey, err := signer.Create()
	if err != nil {
		t.Fatal(err)
	}
	targetsKey, err := signer.Create()
	if err != nil {
		t.Fatal(err)
	}
	snapshotKey, err := signer.Create()
	if err != nil {
		t.Fatal(err)
	}
	timestampKey, err := signer.Create()
	if err != nil {
		t.Fatal(err)
	}

	keyDB := keys.NewDB()
	keyDB.AddKey(rootKey)
	keyDB.AddKey(targetsKey)
	keyDB.AddKey(snapshotKey)
	keyDB.AddKey(timestampKey)

	rootRole := &data.Role{
		Name: "root",
		RootRole: data.RootRole{
			KeyIDs:    []string{rootKey.ID()},
			Threshold: 1,
		},
	}
	targetsRole := &data.Role{
		Name: "targets",
		RootRole: data.RootRole{
			KeyIDs:    []string{targetsKey.ID()},
			Threshold: 1,
		},
	}
	snapshotRole := &data.Role{
		Name: "snapshot",
		RootRole: data.RootRole{
			KeyIDs:    []string{snapshotKey.ID()},
			Threshold: 1,
		},
	}
	timestampRole := &data.Role{
		Name: "timestamp",
		RootRole: data.RootRole{
			KeyIDs:    []string{timestampKey.ID()},
			Threshold: 1,
		},
	}

	keyDB.AddRole(rootRole)
	keyDB.AddRole(targetsRole)
	keyDB.AddRole(snapshotRole)
	keyDB.AddRole(timestampRole)

	repo := NewTufRepo(keyDB, signer)
	err = repo.InitRepo(false)
	if err != nil {
		t.Fatal(err)
	}

	err = os.MkdirAll("/tmp/tufrepo", 0755)
	if err != nil {
		t.Fatal(err)
	}

	signedRoot, err := repo.SignRoot(data.DefaultExpires("root"))
	if err != nil {
		t.Fatal(err)
	}
	rootJSON, _ := json.Marshal(signedRoot)
	ioutil.WriteFile("/tmp/tufrepo/root.json", rootJSON, 0755)

	signedTargets, err := repo.SignTargets("targets", data.DefaultExpires("targets"))
	if err != nil {
		t.Fatal(err)
	}
	targetsJSON, _ := json.Marshal(signedTargets)
	ioutil.WriteFile("/tmp/tufrepo/targets.json", targetsJSON, 0755)

	signedSnapshot, err := repo.SignSnapshot(data.DefaultExpires("snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	snapshotJSON, _ := json.Marshal(signedSnapshot)
	ioutil.WriteFile("/tmp/tufrepo/snapshot.json", snapshotJSON, 0755)

	signedTimestamp, err := repo.SignTimestamp(data.DefaultExpires("timestamp"))
	if err != nil {
		t.Fatal(err)
	}
	timestampJSON, _ := json.Marshal(signedTimestamp)
	ioutil.WriteFile("/tmp/tufrepo/timestamp.json", timestampJSON, 0755)
}
