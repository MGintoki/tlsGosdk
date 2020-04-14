package gosdk

import "time"

type symmetricKey struct {
	sessionId        string
	isResumption     bool
	symmetricKeyType string
	cipherSuite      cipherSuite
	createdAt        time.Time
	expiresAT        time.Time
}
