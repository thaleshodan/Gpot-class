package firewall

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
	"math/rand"
	"sync/atomic"
)

// Configurações do firewall
type Config struct {
	MaxAttempts    int           // Máximo de tentativas antes de banir
	BanDuration    time.Duration // Duração do banimento
	AllowedIPs     []string      // Lista de IPs permitidos
	LogFile        string        // Arquivo de log
	CleanUpInterval time.Duration // Intervalo para limpeza dos banidos
}

// Firewall gerencia as regras e controle de tráfego
type Firewall struct {
	allowedIPs    map[string]bool
	bannedIPs     map[string]time.Time
	maxAttempts   int
	banDuration   time.Duration
	cleanUpInterval time.Duration
	allowedIPsCount int32 // Contador atômico de IPs permitidos
	bannedIPsCount int32  // Contador atômico de IPs banidos
	mu            sync.Mutex
	logger        *log.Logger
}

// Nova instância do Firewall
func NewFirewall(config *Config) *Firewall {
	// Logger configurado
	logger := log.New(log.Writer(), "FIREWALL: ", log.LstdFlags|log.Lshortfile)
	return &Firewall{
		allowedIPs:     make(map[string]bool),
		bannedIPs:      make(map[string]time.Time),
		maxAttempts:    config.MaxAttempts,
		banDuration:    config.BanDuration,
		cleanUpInterval: config.CleanUpInterval,
		logger:         logger,
	}
}

// Verifica se o IP está banido
func (fw *Firewall) isBanned(ip string) bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if banTime, exists := fw.bannedIPs[ip]; exists {
		if time.Since(banTime) > fw.banDuration {
			delete(fw.bannedIPs, ip)
			atomic.AddInt32(&fw.bannedIPsCount, -1)
			return false
		}
		return true
	}
	return false
}

// Adiciona IP à lista de banidos
func (fw *Firewall) banIP(ip string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.bannedIPs[ip] = time.Now()
	atomic.AddInt32(&fw.bannedIPsCount, 1)
	fw.logger.Printf("IP %s banido devido ao excesso de tentativas\n", ip)
}

// Permite uma nova conexão para um IP
func (fw *Firewall) allowConnection(ip string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if _, exists := fw.allowedIPs[ip]; !exists {
		fw.allowedIPs[ip] = true
		atomic.AddInt32(&fw.allowedIPsCount, 1)
		fw.logger.Printf("IP %s permitido para conexão\n", ip)
	}
}

// HandleConnection simula o processo de verificar e permitir/rejeitar conexões
func (fw *Firewall) handleConnection(ctx context.Context, ip string) {
	if fw.isBanned(ip) {
		fw.logger.Printf("Conexão rejeitada: IP %s está banido\n", ip)
		return
	}

	// Simula tentativas de login
	attempts := 0
	for attempts < fw.maxAttempts {
		select {
		case <-ctx.Done():
			fw.logger.Println("Operação cancelada")
			return
		default:
			attempts++
			fw.logger.Printf("Tentativa %d de %d para %s\n", attempts, fw.maxAttempts, ip)

			if attempts >= fw.maxAttempts {
				fw.banIP(ip)
			}
		}
	}
}

// Limpeza periódica dos IPs banidos
func (fw *Firewall) cleanUpBannedIPs() {
	for {
		select {
		case <-time.After(fw.cleanUpInterval):
			fw.mu.Lock()
			for ip, banTime := range fw.bannedIPs {
				if time.Since(banTime) > fw.banDuration {
					delete(fw.bannedIPs, ip)
					atomic.AddInt32(&fw.bannedIPsCount, -1)
				}
			}
			fw.mu.Unlock()
			fw.logger.Println("Limpeza de IPs banidos realizada")
		}
	}
}

// Monitoramento do tráfego para um IP
func (fw *Firewall) monitorTraffic(ctx context.Context, ip string) {
	select {
	case <-ctx.Done():
		fw.logger.Println("Monitoramento de tráfego cancelado")
		return
	default:
		fw.handleConnection(ctx, ip)
	}
}

// MonitorIP inicia o monitoramento de tráfego de um IP
func (fw *Firewall) MonitorIP(ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fw.monitorTraffic(ctx, ip)
}

// StartFirewall inicia o servidor de firewall para gerenciar conexões
func (fw *Firewall) startFirewall() {
	go fw.cleanUpBannedIPs() // Inicia a limpeza periódica

	// Simula alguns IPs para conexão
	ips := []string{
		"192.168.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.2",
		"10.0.0.2",
	}

	// Simula o processo de monitoramento
	for _, ip := range ips {
		go fw.MonitorIP(ip)
	}
}

// Main para execução do firewall
func main() {
	// Configuração do firewall
	config := &Config{
		MaxAttempts:    5,
		BanDuration:    1 * time.Hour,
		CleanUpInterval: 30 * time.Minute,
		LogFile:        "firewall_logs.txt",
	}

	// Criação do firewall
	firewall := NewFirewall(config)

	// Início do firewall
	firewall.startFirewall()
}

