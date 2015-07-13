package signed

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"reflect"

	"github.com/Sirupsen/logrus"
	"github.com/agl/ed25519"
	"github.com/endophage/gotuf/data"
)

// Verifiers serves as a map of all verifiers available on the system and
// can be injected into a verificationService. For testing and configuration
// purposes, it will not be used by default.
var Verifiers = map[data.SigAlgorithm]Verifier{
	data.RSAPSSSignature:   RSAPSSVerifier{},
	data.PyCryptoSignature: RSAPyCryptoVerifier{},
	data.ECDSASignature:    ECDSAVerifier{},
	data.EDDSASignature:    Ed25519Verifier{},
}

// RegisterVerifier provides a convenience function for init() functions
// to register additional verifiers or replace existing ones.
func RegisterVerifier(algorithm data.SigAlgorithm, v Verifier) {
	curr, ok := Verifiers[algorithm]
	if ok {
		typOld := reflect.TypeOf(curr)
		typNew := reflect.TypeOf(v)
		logrus.Debugf(
			"replacing already loaded verifier %s:%s with %s:%s",
			typOld.PkgPath(), typOld.Name(),
			typNew.PkgPath(), typNew.Name(),
		)
	} else {
		logrus.Debug("adding verifier for: ", algorithm)
	}
	Verifiers[algorithm] = v
}

type Ed25519Verifier struct{}

func (v Ed25519Verifier) Verify(key data.Key, sig []byte, msg []byte) error {
	var sigBytes [ed25519.SignatureSize]byte
	if len(sig) != len(sigBytes) {
		logrus.Infof("signature length is incorrect, must be %d, was %d.", ed25519.SignatureSize, len(sig))
		return ErrInvalid
	}
	copy(sigBytes[:], sig)

	var keyBytes [ed25519.PublicKeySize]byte
	copy(keyBytes[:], key.Public())

	if !ed25519.Verify(&keyBytes, msg, &sigBytes) {
		logrus.Infof("failed ed25519 verification")
		return ErrInvalid
	}
	return nil
}

func verifyPSS(key interface{}, digest, sig []byte) error {
	rsaPub, ok := key.(*rsa.PublicKey)
	if !ok {
		logrus.Infof("value was not an RSA public key")
		return ErrInvalid
	}

	opts := rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256}
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], sig, &opts); err != nil {
		logrus.Infof("failed RSAPSS verification: %s", err)
		return ErrInvalid
	}
	return nil
}

// RSAPSSVerifier checks RSASSA-PSS signatures
type RSAPSSVerifier struct{}

// Verify does the actual check.
func (v RSAPSSVerifier) Verify(key data.Key, sig []byte, msg []byte) error {
	algorithm := key.Algorithm()
	var pubKey crypto.PublicKey

	switch algorithm {
	case data.RSAx509Key:
		pemCert, _ := pem.Decode([]byte(key.Public()))
		if pemCert == nil {
			logrus.Infof("failed to decode PEM-encoded x509 certificate")
			return ErrInvalid
		}
		cert, err := x509.ParseCertificate(pemCert.Bytes)
		if err != nil {
			logrus.Infof("failed to parse x509 certificate: %s\n", err)
			return ErrInvalid
		}
		pubKey = cert.PublicKey
	case data.RSAKey:
		var err error
		pubKey, err = x509.ParsePKIXPublicKey(key.Public())
		if err != nil {
			logrus.Infof("failed to parse public key: %s\n", err)
			return ErrInvalid
		}
	default:
		logrus.Infof("invalid key type for RSAPSS verifier: %s", algorithm)
		return ErrInvalid
	}

	digest := sha256.Sum256(msg)

	return verifyPSS(pubKey, digest[:], sig)
}

// RSAPSSVerifier checks RSASSA-PSS signatures
type RSAPyCryptoVerifier struct{}

// Verify does the actual check.
// N.B. We have not been able to make this work in a way that is compatible
// with PyCrypto.
func (v RSAPyCryptoVerifier) Verify(key data.Key, sig []byte, msg []byte) error {
	digest := sha256.Sum256(msg)

	k, _ := pem.Decode([]byte(key.Public()))
	if k == nil {
		logrus.Infof("failed to decode PEM-encoded x509 certificate")
		return ErrInvalid
	}

	pub, err := x509.ParsePKIXPublicKey(k.Bytes)
	if err != nil {
		logrus.Infof("failed to parse public key: %s\n", err)
		return ErrInvalid
	}

	return verifyPSS(pub, digest[:], sig)
}

// ECDSAVerifier checks ECDSA signatures, decoding the keyType appropriately
type ECDSAVerifier struct{}

// Verify does the actual check.
func (v ECDSAVerifier) Verify(key data.Key, sig []byte, msg []byte) error {
	algorithm := key.Algorithm()
	var pubKey crypto.PublicKey

	switch algorithm {
	case data.ECDSAx509Key:
		pemCert, _ := pem.Decode([]byte(key.Public()))
		if pemCert == nil {
			logrus.Infof("failed to decode PEM-encoded x509 certificate for keyID: %s", key.ID())
			logrus.Debugf("certificate bytes: %s", string(key.Public()))
			return ErrInvalid
		}
		cert, err := x509.ParseCertificate(pemCert.Bytes)
		if err != nil {
			logrus.Infof("failed to parse x509 certificate: %s\n", err)
			return ErrInvalid
		}
		pubKey = cert.PublicKey
	case data.ECDSAKey:
		var err error
		pubKey, err = x509.ParsePKIXPublicKey(key.Public())
		if err != nil {
			logrus.Infof("Failed to parse private key for keyID: %s, %s\n", key.ID(), err)
			return ErrInvalid
		}
	default:
		logrus.Infof("invalid key type for ECDSA verifier: %s", algorithm)
		return ErrInvalid
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		logrus.Infof("value isn't an ECDSA public key")
		return ErrInvalid
	}

	sigLength := len(sig)
	expectedOctetLength := 2 * ((ecdsaPubKey.Params().BitSize + 7) >> 3)
	if sigLength != expectedOctetLength {
		logrus.Infof("signature had an unexpected length")
		return ErrInvalid
	}

	rBytes, sBytes := sig[:sigLength/2], sig[sigLength/2:]
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	digest := sha256.Sum256(msg)

	if !ecdsa.Verify(ecdsaPubKey, digest[:], r, s) {
		logrus.Infof("failed ECDSA signature validation")
		return ErrInvalid
	}

	return nil
}
