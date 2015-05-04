package signed

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"log"
	"reflect"

	"github.com/Sirupsen/logrus"
	"github.com/agl/ed25519"
	"github.com/endophage/go-tuf/data"
)

// Verifiers serves as a map of all verifiers available on the system and
// can be injected into a verificationService. For testing and configuration
// purposes, it will not be used by default.
var Verifiers = map[string]Verifier{
	"ed25519": Ed25519Verifier{},
	"rsa":     RSAVerifier{},
}

// RegisterVerifier provides a convenience function for init() functions
// to register additional verifiers or replace existing ones.
func RegisterVerifier(name string, v Verifier) {
	curr, ok := Verifiers[name]
	if ok {
		typOld := reflect.TypeOf(curr)
		typNew := reflect.TypeOf(v)
		logrus.Debugf(
			"Replacing already loaded verifier %s:%s with %s:%s",
			typOld.PkgPath(), typOld.Name(),
			typNew.PkgPath(), typNew.Name(),
		)
	} else {
		logrus.Debug("Adding verifier for: ", name)
	}
	Verifiers[name] = v
}

type Ed25519Verifier struct{}

func (v Ed25519Verifier) Verify(key *data.Key, sig []byte, msg []byte) error {
	logrus.Info("Verifying signature with Ed25519")
	var sigBytes [ed25519.SignatureSize]byte
	if len(sig) != len(sigBytes) {
		logrus.Infof("Signature length is incorrect, must be %d, was %d.", ed25519.SignatureSize, len(sig))
		return ErrInvalid
	}
	copy(sigBytes[:], sig)

	var keyBytes [ed25519.PublicKeySize]byte
	copy(keyBytes[:], key.Value.Public)

	if !ed25519.Verify(&keyBytes, msg, &sigBytes) {
		logrus.Infof("Failed ed25519 verification")
		return ErrInvalid
	}
	log.Printf("---------------Verification succeeded!!!---------------")
	return nil
}

type RSAVerifier struct{}

func (v RSAVerifier) Verify(key *data.Key, sig []byte, msg []byte) error {
	logrus.Infof("Verifying signature with RSA %d", len(sig)*8)
	digest := sha256.Sum256(msg)
	pub, err := x509.ParsePKIXPublicKey(key.Value.Public)
	if err != nil {
		logrus.Infof("Failed to parse public key: %s\n", err)
		return ErrInvalid
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		logrus.Infof("Value returned from ParsePKIXPublicKey was not an RSA public key")
		return ErrInvalid
	}

	if err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
		logrus.Infof("Failed verification: %s", err)
		return ErrInvalid
	}
	log.Printf("---------------Verification succeeded!!!---------------")
	return nil
}
