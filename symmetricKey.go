package gosdk

import "time"

type SymmetricKey struct {
	sessionId        string
	isResumption     bool
	symmetricKeyType string
	cipherSuite      CipherSuite
	createdAt        time.Time
	expiresAT        time.Time
}
