package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	Sign(dataToBeSigned []byte) ([]byte, error)
}

// RSASigner signs data using an RSA private key.
type RSASigner struct {
	privateKey *rsa.PrivateKey
}

// NewRSASigner creates a new RSASigner with the given RSA private key.
func NewRSASigner(privateKey *rsa.PrivateKey) *RSASigner {
	return &RSASigner{
		privateKey: privateKey,
	}
}

// Sign signs the given data using the RSA private key.
func (s *RSASigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	hashed := sha256.Sum256(dataToBeSigned)
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// ECDSASigner is an implementation of the Signer interface that uses ECDSA to sign data.
type ECDSASigner struct {
	key *ecdsa.PrivateKey
}

// NewECDSASigner creates a new ECDSASigner with the given private key.
func NewECDSASigner(key *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{key: key}
}

// Sign uses ECDSA to sign the given data and returns the resulting signature.
func (s *ECDSASigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	r, ss, err := ecdsa.Sign(nil, s.key, dataToBeSigned)
	if err != nil {
		return nil, err
	}

	// Concatenate the R and S values into a single byte slice.
	signature := append(r.Bytes(), ss.Bytes()...)

	return signature, nil
}
