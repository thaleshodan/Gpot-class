package firewall

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Port representa uma porta de serviço exposta
type Port struct {
	PortNumber  int    // Número da porta
	Protocol    string // Protocolo associado (ex: TCP, UDP)
	ServiceName string // Nome do serviço (ex: SSH, FTP)
	IsOpen      bool   // Indica se a porta está aberta ou fechada
}

// PortManager gerencia as portas expostas e seu status
type PortManager struct {
	ports           map[int]*Port          // Map de portas e seus status
	mutex           sync.RWMutex           // Para controle de concorrência
	openPorts       map[int]*Port          // Portas abertas
	closedPorts     map[int]*Port          // Portas fechadas
	allowedIPs      map[string]bool        // IPs permitidos para acessar as portas
	ipLock          sync.RWMutex           // Para controle de concorrência em IPs
	logger          *log.Logger            // Logger para registro das operações
	maxConnAttempts int                    // Tentativas máximas de conexão
}

// Nova instância do PortManager
func NewPortManager() *PortManager {
	// Logger configurado
	logger := log.New(log.Writer(), "PORT MANAGER: ", log.LstdFlags|log.Lshortfile)

	// Inicializando as portas do honeypot
	ports := map[int]*Port{
		22:  {PortNumber: 22, Protocol: "TCP", ServiceName: "SSH", IsOpen: true},
		23:  {PortNumber: 23, Protocol: "TCP", ServiceName: "Telnet", IsOpen: true},
		21:  {PortNumber: 21, Protocol: "TCP", ServiceName: "FTP", IsOpen: true},
		80:  {PortNumber: 80, Protocol: "TCP", ServiceName: "HTTP", IsOpen: true},
		443: {PortNumber: 443, Protocol: "TCP", ServiceName: "HTTPS", IsOpen: false},
	}

	return &PortManager{
		ports:       ports,
		openPorts:   make(map[int]*Port),
		closedPorts: make(map[int]*Port),
		allowedIPs:  make(map[string]bool),
		logger:      logger,
	}
}

// Adiciona uma porta à lista de portas abertas
func (pm *PortManager) openPort(portNumber int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	port, exists := pm.ports[portNumber]
	if exists && !port.IsOpen {
		port.IsOpen = true
		pm.openPorts[portNumber] = port
		pm.logger.Printf("Porta %d aberta para o serviço %s.\n", portNumber, port.ServiceName)
	}
}

// Fecha uma porta
func (pm *PortManager) closePort(portNumber int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	port, exists := pm.ports[portNumber]
	if exists && port.IsOpen {
		port.IsOpen = false
		delete(pm.openPorts, portNumber)
		pm.closedPorts[portNumber] = port
		pm.logger.Printf("Porta %d fechada para o serviço %s.\n", portNumber, port.ServiceName)
	}
}

// Verifica se uma porta está aberta
func (pm *PortManager) isPortOpen(portNumber int) bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	port, exists := pm.ports[portNumber]
	if exists && port.IsOpen {
		return true
	}
	return false
}

// Gerencia a conexão de um IP específico
func (pm *PortManager) manageConnection(ip string, portNumber int) {
	pm.ipLock.Lock()
	defer pm.ipLock.Unlock()

	// Verifica se o IP está na lista de permitidos
	if !pm.allowedIPs[ip] {
		pm.logger.Printf("Conexão rejeitada: IP %s não permitido.\n", ip)
		return
	}

	// Verifica o status da porta
	if !pm.isPortOpen(portNumber) {
		pm.logger.Printf("Conexão rejeitada: Porta %d está fechada.\n", portNumber)
		return
	}

	// Simula a tentativa de conexão
	attempts := 0
	for attempts < pm.maxConnAttempts {
		attempts++
		pm.logger.Printf("Tentativa %d de %d para o IP %s na porta %d\n", attempts, pm.maxConnAttempts, ip, portNumber)

		// Exemplo de banimento após o máximo de tentativas
		if attempts >= pm.maxConnAttempts {
			pm.logger.Printf("IP %s bloqueado por tentativas excessivas.\n", ip)
			// Aqui você pode banir o IP ou tomar outras ações
		}
	}
}

// Bloqueia um IP após múltiplas tentativas falhas
func (pm *PortManager) blockIP(ip string) {
	pm.ipLock.Lock()
	defer pm.ipLock.Unlock()

	if !pm.allowedIPs[ip] {
		pm.logger.Printf("IP %s já está bloqueado por múltiplas tentativas.\n", ip)
		return
	}

	pm.allowedIPs[ip] = false
	pm.logger.Printf("IP %s foi bloqueado após múltiplas tentativas falhas.\n", ip)
}

// Monitoramento de tráfego
func (pm *PortManager) monitorTraffic(ip string) {
	// Exemplo de monitoramento de tráfego
	for portNumber := range pm.openPorts {
		go pm.manageConnection(ip, portNumber)
	}
}

// Inicia o monitoramento de todas as portas abertas
func (pm *PortManager) startMonitoring() {
	for ip := range pm.allowedIPs {
		go pm.monitorTraffic(ip)
	}
}

// Exemplo de configuração e uso do PortManager
func main() {
	// Criação do PortManager
	portManager := NewPortManager()
	portManager.maxConnAttempts = 3 // Definindo o número máximo de tentativas

	// Abertura e fechamento de portas
	portManager.openPort(80)  // Abrir HTTP
	portManager.openPort(22)  // Abrir SSH
	portManager.closePort(443) // Fechar HTTPS

	// Monitorando as conexões
	portManager.allowedIPs["192.168.0.10"] = true
	portManager.monitorTraffic("192.168.0.10")
	portManager.startMonitoring()

	// Bloquear um IP por falhas em tentativas de conexão
	portManager.blockIP("192.168.0.10")

	// Simulando o fechamento de uma porta
	portManager.closePort(22)
}
