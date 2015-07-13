package signed

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/endophage/gotuf/data"
	"github.com/endophage/gotuf/keys"
	"github.com/tent/canonical-json-go"
)

var (
	ErrMissingKey    = errors.New("tuf: missing key")
	ErrNoSignatures  = errors.New("tuf: data has no signatures")
	ErrInvalid       = errors.New("tuf: signature verification failed")
	ErrWrongMethod   = errors.New("tuf: invalid signature type")
	ErrUnknownRole   = errors.New("tuf: unknown role")
	ErrRoleThreshold = errors.New("tuf: valid signatures did not meet threshold")
	ErrWrongType     = errors.New("tuf: meta file has wrong type")
)

type signedMeta struct {
	Type    string `json:"_type"`
	Expires string `json:"expires"`
	Version int    `json:"version"`
}

// VerifyRoot checks if a given root file is valid against a known set of keys.
func VerifyRoot(s *data.Signed, minVersion int, keys map[string]*data.PublicKey, threshold int) ([]*data.PublicKey, error) {
	if len(s.Signatures) == 0 {
		return nil, ErrNoSignatures
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(s.Signed, &decoded); err != nil {
		return nil, err
	}
	msg, err := cjson.Marshal(decoded)
	if err != nil {
		return nil, err
	}

	valid := make(map[string]struct{})
	for _, sig := range s.Signatures {
		// method lookup is consistent due to Unmarshal JSON doing lower case for us.
		method := sig.Method
		verifier, ok := Verifiers[method]
		if !ok {
			logrus.Debugf("continuing b/c signing method is not supported for verify root: %s\n", sig.Method)
			continue
		}

		if err := verifier.Verify(keys[sig.KeyID], sig.Signature, msg); err != nil {
			logrus.Debugf("continuing b/c signature was invalid\n")
			continue
		}
		valid[sig.KeyID] = struct{}{}

	}
	if len(valid) < threshold {
		return nil, ErrRoleThreshold
	}
	return nil, verifyMeta(s, "root", minVersion)
}

func Verify(s *data.Signed, role string, minVersion int, db *keys.KeyDB) error {
	if err := VerifySignatures(s, role, db); err != nil {
		return err
	}
	return verifyMeta(s, role, minVersion)
}

func verifyMeta(s *data.Signed, role string, minVersion int) error {
	sm := &signedMeta{}
	if err := json.Unmarshal(s.Signed, sm); err != nil {
		return err
	}
	if !data.ValidTUFType(sm.Type) {
		return ErrWrongType
	}
	if IsExpired(sm.Expires) {
		logrus.Errorf("Metadata for %s expired", role)
		return ErrExpired{sm.Expires}
	}
	if sm.Version < minVersion {
		return ErrLowVersion{sm.Version, minVersion}
	}

	return nil
}

var IsExpired = func(t string) bool {
	ts, err := time.Parse(time.RFC3339, t)
	if err != nil {
		ts, err = time.Parse("2006-01-02 15:04:05 MST", t)
		if err != nil {
			return false
		}
	}
	return ts.Sub(time.Now()) <= 0
}

func VerifySignatures(s *data.Signed, role string, db *keys.KeyDB) error {
	if len(s.Signatures) == 0 {
		return ErrNoSignatures
	}

	roleData := db.GetRole(role)
	if roleData == nil {
		return ErrUnknownRole
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(s.Signed, &decoded); err != nil {
		return err
	}
	msg, err := cjson.Marshal(decoded)
	if err != nil {
		return err
	}

	valid := make(map[string]struct{})
	for _, sig := range s.Signatures {
		if !roleData.ValidKey(sig.KeyID) {
			logrus.Debugf("continuing b/c keyid was invalid: %s for roledata %s\n", sig.KeyID, roleData)
			continue
		}
		key := db.GetKey(sig.KeyID)
		if key == nil {
			logrus.Debugf("continuing b/c keyid lookup was nil: %s\n", sig.KeyID)
			continue
		}
		// method lookup is consistent due to Unmarshal JSON doing lower case for us.
		method := sig.Method
		verifier, ok := Verifiers[method]
		if !ok {
			logrus.Debugf("continuing b/c signing method is not supported: %s\n", sig.Method)
			continue
		}

		if err := verifier.Verify(key, sig.Signature, msg); err != nil {
			logrus.Debugf("continuing b/c signature was invalid\n")
			continue
		}
		valid[sig.KeyID] = struct{}{}

	}
	if len(valid) < roleData.Threshold {
		return ErrRoleThreshold
	}

	return nil
}

func Unmarshal(b []byte, v interface{}, role string, minVersion int, db *keys.KeyDB) error {
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	if err := Verify(s, role, minVersion, db); err != nil {
		return err
	}
	return json.Unmarshal(s.Signed, v)
}

func UnmarshalTrusted(b []byte, v interface{}, role string, db *keys.KeyDB) error {
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	if err := VerifySignatures(s, role, db); err != nil {
		return err
	}
	return json.Unmarshal(s.Signed, v)
}
