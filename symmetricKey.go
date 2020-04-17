package gosdk

import "time"

type SymmetricKey struct {
	SessionId    string      `json:"sessionId"`
	IsResumption bool        `json:"isResumption"`
	KeyType      string      `json:"keyType"`
	CipherSuite  CipherSuite `json:"cipherSuite"`
	CreatedAt    time.Time   `json:"createdAt"`
	ExpiresAT    time.Time   `json:"expiresAt"`
}
