package data

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
)

type KeyAlgorithm string

func (k KeyAlgorithm) String() string {
	return string(k)
}

type SigAlgorithm string

func (k SigAlgorithm) String() string {
	return string(k)
}

const (
	defaultHashAlgorithm = "sha256"

	EDDSASignature    SigAlgorithm = "eddsa"
	RSAPSSSignature   SigAlgorithm = "rsapss"
	ECDSASignature    SigAlgorithm = "ecdsa"
	PyCryptoSignature SigAlgorithm = "pycrypto-pkcs#1 pss"

	ED25519Key   KeyAlgorithm = "ed25519"
	RSAKey       KeyAlgorithm = "rsa"
	RSAx509Key   KeyAlgorithm = "rsa-x509"
	ECDSAKey     KeyAlgorithm = "ecdsa"
	ECDSAx509Key KeyAlgorithm = "ecdsa-x509"
)

var TUFTypes = map[string]string{
	"targets":   "Targets",
	"root":      "Root",
	"snapshot":  "Snapshot",
	"timestamp": "Timestamp",
}

// SetTUFTypes allows one to override some or all of the default
// type names in TUF.
func SetTUFTypes(ts map[string]string) {
	for k, v := range ts {
		TUFTypes[k] = v
	}
}

// Checks if type is correct.
func ValidTUFType(t string) bool {
	// most people will just use the defaults so have this optimal check
	// first. Do comparison just in case there is some unknown vulnerability
	// if a key and value in the map differ.
	if v, ok := TUFTypes[t]; ok {
		return t == v
	}
	// For people that feel the need to change the default type names.
	for _, v := range TUFTypes {
		if t == v {
			return true
		}
	}
	return false
}

type Signed struct {
	Signed     json.RawMessage `json:"signed"`
	Signatures []Signature     `json:"signatures"`
}

type Signature struct {
	KeyID     string       `json:"keyid"`
	Method    SigAlgorithm `json:"method"`
	Signature HexBytes     `json:"sig"`
}

type Files map[string]FileMeta

type Hashes map[string]HexBytes

type FileMeta struct {
	Length int64            `json:"length"`
	Hashes Hashes           `json:"hashes"`
	Custom *json.RawMessage `json:"custom,omitempty"`
}

func NewFileMeta(r io.Reader, hashAlgorithms ...string) (FileMeta, error) {
	if len(hashAlgorithms) == 0 {
		hashAlgorithms = []string{defaultHashAlgorithm}
	}
	hashes := make(map[string]hash.Hash, len(hashAlgorithms))
	for _, hashAlgorithm := range hashAlgorithms {
		var h hash.Hash
		switch hashAlgorithm {
		case "sha256":
			h = sha256.New()
		case "sha512":
			h = sha512.New()
		default:
			return FileMeta{}, fmt.Errorf("Unknown Hash Algorithm: %s", hashAlgorithm)
		}
		hashes[hashAlgorithm] = h
		r = io.TeeReader(r, h)
	}
	n, err := io.Copy(ioutil.Discard, r)
	if err != nil {
		return FileMeta{}, err
	}
	m := FileMeta{Length: n, Hashes: make(Hashes, len(hashes))}
	for hashAlgorithm, h := range hashes {
		m.Hashes[hashAlgorithm] = h.Sum(nil)
	}
	return m, nil
}

type Delegations struct {
	Keys  map[string]*PublicKey `json:"keys"`
	Roles []*Role               `json:"roles"`
}

func NewDelegations() *Delegations {
	return &Delegations{
		Keys:  make(map[string]*PublicKey),
		Roles: make([]*Role, 0),
	}
}

var defaultExpiryTimes = map[string]time.Time{
	"root":      time.Now().AddDate(1, 0, 0),
	"targets":   time.Now().AddDate(0, 3, 0),
	"snapshot":  time.Now().AddDate(0, 0, 7),
	"timestamp": time.Now().AddDate(0, 0, 1),
}

// SetDefaultExpiryTimes allows one to change the default expiries.
func SetDefaultExpiryTimes(times map[string]time.Time) {
	for key, value := range times {
		if _, ok := defaultExpiryTimes[key]; !ok {
			logrus.Errorf("Attempted to set default expiry for an unknown role: %s", key)
			continue
		}
		defaultExpiryTimes[key] = value
	}
}

func DefaultExpires(role string) time.Time {
	var t time.Time
	if t, ok := defaultExpiryTimes[role]; ok {
		return t
	}
	return t.UTC().Round(time.Second)
}

type unmarshalledSignature Signature

func (s *Signature) UnmarshalJSON(data []byte) error {
	uSignature := unmarshalledSignature{}
	err := json.Unmarshal(data, &uSignature)
	if err != nil {
		return err
	}
	uSignature.Method = SigAlgorithm(strings.ToLower(string(uSignature.Method)))
	*s = Signature(uSignature)
	return nil
}
