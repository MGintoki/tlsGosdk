package gosdk

import "time"

type SymmetricKey struct {
	SessionId    string    `json:"sessionId"`
	IsResumption bool      `json:"isResumption"`
	KeyType      string    `json:"keyType"`
	Key          []byte    `json:"key"`
	CipherSuite  int       `json:"cipherSuite"`
	CreatedAt    time.Time `json:"createdAt"`
	ExpiresAT    time.Time `json:"expiresAt"`
}
