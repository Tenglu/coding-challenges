package domain

import (
	"github.com/google/uuid"
)

// Device represents a signature device.
type Device struct {
	ID             uuid.UUID
	Algorithm      string
	Label          string
	PrivateKeyByte []byte
	Counter        int
	LastSignature  []byte
}
