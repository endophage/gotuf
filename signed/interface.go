package signed

import (
	"github.com/docker/go-tuf/data"
	"github.com/docker/go-tuf/keys"
)

type Signer interface {
	GetPublicKeys(keyIDs ...string) (map[string]keys.Key, error)
	Sign(keyIDs []string, data json.RawMessage) ([]data.Signature, error)
}
