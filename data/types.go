package data

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
)

var TUFTypes = map[string]string{
	"targets":   "targets",
	"root":      "root",
	"snapshot":  "snapshot",
	"timestamp": "timestamp",
}

// SetTUFTypes allows one to override some or all of the default
// type names in TUF.
func SetTUFTypes(ts map[string]string) {
	for k, v := range ts {
		TUFTypes[k] = v
	}
}

// Checks if type is correct. Lower case for consistency.
func ValidTUFType(t string) bool {
	t = strings.ToLower(t)
	// most people will just use the defaults so have this optimal check
	// first.
	if _, ok := TUFTypes[t]; ok {
		return true
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
	KeyID     string   `json:"keyid"`
	Method    string   `json:"method"`
	Signature HexBytes `json:"sig"`
}

type Files map[string]FileMeta

type Hashes map[string]HexBytes

type FileMeta struct {
	Length int64            `json:"length"`
	Hashes Hashes           `json:"hashes"`
	Custom *json.RawMessage `json:"custom,omitempty"`
}

type Delegations struct {
	Keys  map[string]*TUFKey `json:"keys"`
	Roles []*Role            `json:"roles"`
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

type Root struct {
	Type    string             `json:"_type"`
	Version int                `json:"version"`
	Expires string             `json:"expires"`
	Keys    map[string]*TUFKey `json:"keys"`
	Roles   map[string]*Role   `json:"roles"`

	ConsistentSnapshot bool `json:"consistent_snapshot"`
}

func NewRoot() *Root {
	return &Root{
		Type:               "root",
		Expires:            DefaultExpires("root").String(),
		Keys:               make(map[string]*TUFKey),
		Roles:              make(map[string]*Role),
		ConsistentSnapshot: true,
	}
}

type Snapshot struct {
	Type    string `json:"_type"`
	Version int    `json:"version"`
	Expires string `json:"expires"`
	Meta    Files  `json:"meta"`
}

func NewSnapshot() *Snapshot {
	return &Snapshot{
		Type:    "Snapshot",
		Expires: DefaultExpires("snapshot").String(),
		Meta:    make(Files),
	}
}

func (sp *Snapshot) hashForRole(role string) HexBytes {
	return sp.Meta[role].Hashes["sha256"]
}

//type Hashes map[string]HexBytes

//type FileMeta struct {
//	Length int64            `json:"length"`
//	Hashes Hashes           `json:"hashes"`
//	Custom *json.RawMessage `json:"custom,omitempty"`
//}
//
//func (f FileMeta) HashAlgorithms() []string {
//	funcs := make([]string, 0, len(f.Hashes))
//	for name := range f.Hashes {
//		funcs = append(funcs, name)
//	}
//	return funcs
//}
//
//type Targets struct {
//	Type    string    `json:"_type"`
//	Version int       `json:"version"`
//	Expires time.Time `json:"expires"`
//	Targets Files     `json:"targets"`
//}
//
//func NewTargets() *Targets {
//	return &Targets{
//		Type:    "Targets",
//		Expires: DefaultExpires("targets"),
//		Targets: make(Files),
//	}
//}

type Timestamp struct {
	Type    string `json:"_type"`
	Version int    `json:"version"`
	Expires string `json:"expires"`
	Meta    Files  `json:"meta"`
}

func NewTimestamp() *Timestamp {
	return &Timestamp{
		Type:    "Timestamp",
		Expires: DefaultExpires("timestamp").String(),
		Meta:    make(Files),
	}
}
