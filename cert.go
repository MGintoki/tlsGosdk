package gosdk

type CertLoader interface {
	GetCert(cipherSuite int) []byte
	GetCertChain(cipherSuite int) [][]byte
}
