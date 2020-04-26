package gosdk

type TlsServer struct {
	ServerInfo string     `json:"serverInfo"`
	ListenPath string     `json:"listenPath"`
	TlsConfig  *TlsConfig `json:"tlsConfig"`
}
