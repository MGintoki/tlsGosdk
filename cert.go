package gosdk

type CertLoaderInterface interface {
	GetCert(cipherSuite int) []byte
	GetCertChain(cipherSuite int) [][]byte
}
