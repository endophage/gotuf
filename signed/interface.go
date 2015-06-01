package signed

import (
	"github.com/endophage/go-tuf/data"
)

type SigningService interface {
	Sign(keyIDs []string, data []byte) ([]data.Signature, error)
}

type KeyService interface {
	Create() (*data.PublicKey, error)
	PublicKeys(keyIDs ...string) (map[string]*data.PublicKey, error)
}

type CryptoService interface {
	SigningService
	KeyService
}

type Verifier interface {
	Verify(key data.Key, sig []byte, msg []byte) error
}
