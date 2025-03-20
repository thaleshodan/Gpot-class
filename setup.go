package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SSHPort    int    `yaml:"ssh_port"`
	TelnetPort int    `yaml:"telnet_port"`
	FTPPort    int    `yaml:"ftp_port"`
	LogFile    string `yaml:"log_file"`
}

const configPath = "config/config.yaml"

func main() {
	fmt.Println("[+] Iniciando setup do honeypot...")

	// Carregar configuração
	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("[!] Erro ao carregar configuração: %v", err)
	}

	// Criar diretórios necessários
	createDirectories([]string{"logs", "data", "sessions"})

	// Criar arquivo de log
	setupLogging(config.LogFile)

	// Verificar dependências
	checkDependencies([]string{"iptables", "sqlite3"})

	// Criar banco de dados de logs
	initDatabase("data/logs.db")

	fmt.Println("[✓] Setup concluído com sucesso!")
}

func loadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(file, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func createDirectories(dirs []string) {
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("[!] Erro ao criar diretório %s: %v", dir, err)
		}
		fmt.Printf("[+] Diretório %s criado com sucesso\n", dir)
	}
}

func setupLogging(logFile string) {
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("[!] Erro ao abrir arquivo de log: %v", err)
	}
	log.SetOutput(file)
	log.Println("[+] Logging inicializado.")
}

func checkDependencies(deps []string) {
	for _, dep := range deps {
		if _, err := exec.LookPath(dep); err != nil {
			log.Fatalf("[!] Dependência não encontrada: %s", dep)
		}
		fmt.Printf("[✓] Dependência %s encontrada\n", dep)
	}
}

func initDatabase(dbPath string) {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		file, err := os.Create(dbPath)
		if err != nil {
			log.Fatalf("[!] Erro ao criar banco de dados: %v", err)
		}
		file.Close()
		fmt.Println("[+] Banco de dados criado com sucesso")
	}
}
