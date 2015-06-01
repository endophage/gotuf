package client

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/Sirupsen/logrus"
	tuf "github.com/endophage/go-tuf"
	"github.com/endophage/go-tuf/data"
	"github.com/endophage/go-tuf/keys"
	"github.com/endophage/go-tuf/signed"
	"github.com/endophage/go-tuf/store"
	"github.com/endophage/go-tuf/utils"
)

type Client struct {
	local  *tuf.TufRepo
	remote store.RemoteStore
	keysDB *keys.KeyDB
}

// Update an in memory copy of the TUF Repo. If an error is returned, the
// Client instance should be considered corrupted and discarded as it may
// be left in a partially updated state
func (c *Client) Update() error {
	err := c.update()
	if err != nil {
		switch err.(type) {
		case tuf.ErrSigVerifyFail:
		case tuf.ErrMetaExpired:
		case tuf.ErrLocalRootExpired:
			if err := c.downloadRoot(); err != nil {
				logrus.Errorf("Client Update (Root):", err)
				return err
			}
		default:
			return err
		}
	}
	// If we error again, we now have the latest root and just want to fail
	// out as there's no expectation the problem can be resolved automatically
	return c.update()
}

func (c *Client) update() error {
	err := c.downloadTimestamp()
	if err != nil {
		logrus.Errorf("Client Update (Timestamp):", err)
		return err
	}
	err = c.downloadSnapshot()
	if err != nil {
		logrus.Errorf("Client Update (Snapshot):", err)
		return err
	}
	//err = c.checkRoot()
	//if err != nil {
	//	return err
	//}
	err = c.downloadTargets("targets")
	if err != nil {
		logrus.Errorf("Client Update (Targets):", err)
		return err
	}
	return nil
}

// downloadRoot is responsible for downloading the root.json
func (c *Client) downloadRoot() error {
	logrus.Debug("Download root")
	size := c.local.Snapshot.Meta["root"].Length

	raw, err := c.remote.GetMeta("root", size)
	if err != nil {
		return err
	}
	s := &data.Signed{}
	err = json.Unmarshal(raw, s)
	if err != nil {
		return err
	}
	err = c.verifySigned("root", s, 0)
	if err != nil {
		return err
	}
	r := &data.Root{}
	err = json.Unmarshal(s.Signed, r)
	if err != nil {
		return err
	}
	for kid, key := range r.Keys {
		c.keysDB.AddKey(&data.PublicKey{TUFKey: *key})
		logrus.Debug("Given Key ID:", kid, "\nGenerated Key ID:", key.ID())
	}
	for roleName, role := range r.Roles {
		role.Name = strings.TrimSuffix(roleName, ".txt")
		err := c.keysDB.AddRole(role)
		if err != nil {
			return err
		}
	}
	c.local.SetRoot(r)
	return nil
}

// downloadTimestamp is responsible for downloading the timestamp.json
func (c *Client) downloadTimestamp() error {
	raw, err := c.remote.GetMeta("timestamp", 5<<20)
	if err != nil {
		return err
	}
	s := &data.Signed{}
	err = json.Unmarshal(raw, s)
	if err != nil {
		return err
	}
	err = c.verifySigned("timestamp", s, 0)
	if err != nil {
		return err
	}
	ts := &data.Timestamp{}
	err = json.Unmarshal(s.Signed, ts)
	if err != nil {
		return err
	}
	c.local.SetTimestamp(ts)
	return nil
}

// downloadSnapshot is responsible for downloading the snapshot.json
func (c *Client) downloadSnapshot() error {
	size := c.local.Timestamp.Meta["release.txt"].Length
	raw, err := c.remote.GetMeta("release", size)
	if err != nil {
		return err
	}
	s := &data.Signed{}
	err = json.Unmarshal(raw, s)
	if err != nil {
		return err
	}
	err = c.verifySigned("release", s, 0)
	if err != nil {
		return err
	}
	snap := &data.Snapshot{}
	err = json.Unmarshal(s.Signed, snap)
	if err != nil {
		return err
	}
	c.local.SetSnapshot(snap)
	return nil
}

// downloadTargets is responsible for downloading any targets file
// including delegates roles. It will download the whole tree of
// delegated roles below the given one
func (c *Client) downloadTargets(role string) error {
	snap := c.local.Snapshot
	root := c.local.Root
	r := c.keysDB.GetRole(role)
	if r == nil {
		return fmt.Errorf("Invalid role: %s", role)
	}
	keyIDs := r.KeyIDs
	t, err := c.GetTargetsFile(role, keyIDs, snap.Meta, root.ConsistentSnapshot, r.Threshold)
	if err != nil {
		logrus.Error("Error getting targets file:", err)
		return err
	}
	c.local.SetTargets(role, t)
	for _, r := range t.Delegations.Roles {
		err := c.downloadTargets(r.Name)
		if err != nil {
			logrus.Error("Failed to download ", role, err)
			return err
		}
	}
	return nil
}

// verifySigned checks the Signatures against the Signed field in an instance
// of the Signed struct.
func (c *Client) verifySigned(role string, s *data.Signed, prevVersion int) error {
	if err := signed.Verify(s, role, prevVersion, c.keysDB); err != nil {
		logrus.Error("Failed to verify signature of ", role, ": ", err)
		return fmt.Errorf("Failed to verify signature of %s", role)
	}
	return nil
}

func (c Client) GetTargetsFile(roleName string, keyIDs []string, snapshotMeta data.Files, consistent bool, threshold int) (*data.Targets, error) {
	rolePath, err := c.RoleTargetsPath(roleName, snapshotMeta, consistent)
	if err != nil {
		return nil, err
	}
	r, err := c.remote.GetMeta(rolePath, snapshotMeta[roleName+".txt"].Length)
	if err != nil {
		return nil, err
	}
	s := &data.Signed{}
	err = json.Unmarshal(r, s)
	if err != nil {
		logrus.Error("Error unmarshalling targets file:", err)
		return nil, err
	}
	return c.ValidateTargetsFile(s, roleName)
}

func (c Client) ValidateTargetsFile(s *data.Signed, roleName string) (*data.Targets, error) {
	err := signed.Verify(s, roleName, 0, c.keysDB)
	if err != nil {
		return nil, err
	}
	t := &data.Targets{}
	err = json.Unmarshal(s.Signed, t)
	if err != nil {
		return nil, err
	}
	for _, k := range t.Delegations.Keys {
		c.keysDB.AddKey(&data.PublicKey{TUFKey: *k})
	}
	for _, r := range t.Delegations.Roles {
		c.keysDB.AddRole(r)
	}
	return t, nil
}

func (c Client) RoleTargetsPath(roleName string, snapshotMeta data.Files, consistent bool) (string, error) {
	if consistent {
		roleMeta, ok := snapshotMeta[roleName]
		if !ok {
			return "", fmt.Errorf("Consistent Snapshots Enabled but no meta found for target role")
		}
		if _, ok := roleMeta.Hashes["sha256"]; !ok {
			return "", fmt.Errorf("Consistent Snapshots Enabled and sha256 not found for targets file in snapshot meta")
		}
		dir := filepath.Dir(roleName)
		if strings.Contains(roleName, "/") {
			lastSlashIdx := strings.LastIndex(roleName, "/")
			roleName = roleName[lastSlashIdx+1:]
		}
		roleName = path.Join(
			dir,
			fmt.Sprintf("%s.%s.json", roleMeta.Hashes["sha256"], roleName),
		)

	}
	return roleName, nil
}

func (c Client) TargetMeta(path string) *data.FileMeta {
	return c.local.FindTarget(path)
}

func (c Client) DownloadTarget(dst io.Writer, path string, meta *data.FileMeta) error {
	reader, err := c.remote.GetTarget(path)
	if err != nil {
		return err
	}
	defer reader.Close()
	r := io.TeeReader(
		io.LimitReader(reader, meta.Length),
		dst,
	)
	err = utils.ValidateTarget(r, meta)
	return err
}
