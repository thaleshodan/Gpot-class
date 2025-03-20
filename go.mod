module github.com/thaleshodan/myhoneypot

go 1.21

require (
	github.com/sirupsen/logrus v1.9.0 // Logs avançados
	golang.org/x/crypto v0.15.0       // Algoritmos criptográficos (útil para SSH e autenticação)
	github.com/armon/go-socks5 v0.0.0-20210120193318-cfd40e799cf5 // Proxy SOCKS5
	github.com/spf13/viper v1.16.0    // Leitura de configurações em YAML
	github.com/mattn/go-sqlite3 v1.14.16 // Banco de dados SQLite para logs
)
