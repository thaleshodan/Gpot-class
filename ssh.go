package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"yourproject/internal/logs"  // Log personalizado
	"yourproject/internal/network"  // Lógica de rede separada
)

// SSHServerConfig armazena a configuração do servidor SSH.
type SSHServerConfig struct {
	ListenAddr string
	SSHConfig  *ssh.ServerConfig
}

// NewSSHServerConfig cria uma nova configuração do servidor SSH.
func NewSSHServerConfig(listenAddr string, privateKey []byte) (*SSHServerConfig, error) {
	// Carrega a chave privada do servidor (pode ser uma chave autoassinado para o honeypot)
	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Cria o servidor SSH com configurações básicas
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Aqui podemos simular uma autenticação
			return nil, fmt.Errorf("unauthorized access")
		},
	}

	serverConfig.AddHostKey(private)

	return &SSHServerConfig{
		ListenAddr: listenAddr,
		SSHConfig:  serverConfig,
	}, nil
}

// Start inicia o servidor SSH e escuta conexões.
func (cfg *SSHServerConfig) Start() error {
	// Inicia o servidor para escutar as conexões
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	defer listener.Close()

	log.Printf("Listening for SSH connections on %s...", cfg.ListenAddr)

	// Aceita e lida com as conexões
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// Loga tentativas de conexão
		go logConnectionAttempt(conn.RemoteAddr().String(), true)

		// Lida com a conexão em uma nova goroutine
		go handleSSHConnection(conn, cfg.SSHConfig)
	}
}

// handleSSHConnection trata a conexão SSH, realizando a autenticação e comandos.
func handleSSHConnection(conn net.Conn, serverConfig *ssh.ServerConfig) {
	// Realiza o handshake SSH
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		log.Printf("Failed to establish SSH connection: %v", err)
		return
	}
	defer sshConn.Close()

	log.Printf("New SSH connection from %s", sshConn.RemoteAddr())

	// Lida com os requisições de autenticação
	go ssh.DiscardRequests(reqs)

	// Lida com os canais de sessão SSH (comandos)
	for ch := range chans {
		go handleChannel(ch)
	}
}

// handleChannel lida com o canal de comunicação, simulando um shell.
func handleChannel(ch ssh.NewChannel) {
	// Verifica o tipo do canal (espera por 'session')
	if ch.ChannelType() != "session" {
		ch.Reject(ssh.UnknownChannelType, "only session channels are allowed")
		return
	}

	// Aceita o canal e cria uma sessão
	channel, _, err := ch.Accept()
	if err != nil {
		log.Printf("Failed to accept channel: %v", err)
		return
	}
	defer channel.Close()

	// Simula uma interação de shell, retornando uma mensagem de boas-vindas
	channel.Write([]byte("Welcome to the honeypot! Type 'exit' to quit.\n"))

	// Aguardar comandos do cliente (nesse caso, apenas simula um shell simples)
	handleCommands(channel)
}

// handleCommands processa os comandos simulados de um shell.
func handleCommands(channel ssh.Channel) {
	// Aqui você pode simular a execução de comandos ou responder com algo fixo
	for {
		// Leitura de dados do canal
		// Simulando o recebimento de um comando
		buf := make([]byte, 1024)
		_, err := channel.Read(buf)
		if err != nil {
			log.Printf("Failed to read from channel: %v", err)
			return
		}

		// Simula a resposta a um comando
		// (Por exemplo, qualquer comando gerará uma resposta simulada)
		channel.Write([]byte("Command received: " + string(buf)))
		channel.Write([]byte("\n"))
	}
}

// logConnectionAttempt registra tentativas de conexão no sistema.
func logConnectionAttempt(remoteAddr string, success bool) {
	if success {
		logs.Info(fmt.Sprintf("Successful connection from %s", remoteAddr))
	} else {
		logs.Warn(fmt.Sprintf("Failed connection attempt from %s", remoteAddr))
	}
}

// SSHServer é a interface que abstrai o comportamento do servidor SSH para testes.
type SSHServer interface {
	Start() error
}

// Simula a geração de uma chave privada para o servidor SSH
func generatePrivateKey() ([]byte, error) {
	// Exemplo de chave privada gerada (pode ser autoassinado ou algo mais complexo)
	return []byte(`-----BEGIN OPENSSH PRIVATE KEY-----<private_key_data>-----END OPENSSH PRIVATE KEY-----`), nil
}

// Função principal para iniciar o servidor SSH
func main() {
	// Gera ou carrega uma chave privada para o servidor SSH
	privateKey, err := generatePrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Cria a configuração do servidor SSH
	cfg, err := NewSSHServerConfig("0.0.0.0:2222", privateKey)
	if err != nil {
		log.Fatalf("Failed to create SSH server config: %v", err)
	}

	// Inicia o servidor SSH
	if err := cfg.Start(); err != nil {
		log.Fatalf("Failed to start SSH server: %v", err)
	}
}
