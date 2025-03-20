package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Configurações
var (
	ValidCredentials = map[string]string{
		"admin": "admin",  // Usuário admin com senha admin
		"user":  "password", // Usuário user com senha password
	}

	// Definir o limite de tentativas de login falhas antes de bloquear o IP
	LoginAttemptLimit = 5
	LockDuration      = time.Minute * 5
)

// Configuração de banco de dados
var db *sql.DB

func init() {
	// Inicializando o banco de dados de logs de falhas
	var err error
	db, err = sql.Open("sqlite3", "./honeypot.db")
	if err != nil {
		log.Fatalf("Erro ao conectar ao banco de dados: %v", err)
	}
	createTableIfNotExists()
}

// Cria a tabela de logs de falhas se ela não existir
func createTableIfNotExists() {
	query := `
	CREATE TABLE IF NOT EXISTS failed_logins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Erro ao criar a tabela de logs: %v", err)
	}
}

// Função para autenticar o usuário
func Authenticate(username, password, ipAddress string) (bool, error) {
	// Normaliza o nome de usuário e senha
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)

	// Verifica se o número de tentativas de login falhas excedeu o limite
	attempts, err := getFailedLoginAttempts(username, ipAddress)
	if err != nil {
		log.Printf("Erro ao verificar tentativas de login falhas: %v", err)
	}
	if attempts >= LoginAttemptLimit {
		return false, fmt.Errorf("limite de tentativas de login excedido. Tente novamente mais tarde.")
	}

	// Verifica as credenciais
	if validPassword, exists := ValidCredentials[username]; exists {
		if password == validPassword {
			return true, nil // Sucesso no login
		}
	}

	// Se falhou, registra a tentativa de login falha
	recordFailedLogin(username, ipAddress)

	// Retorna erro de credenciais inválidas
	return false, errors.New("usuário ou senha inválidos")
}

// Função para registrar uma tentativa de login falha
func recordFailedLogin(username, ipAddress string) {
	query := `INSERT INTO failed_logins (username, ip_address) VALUES (?, ?)`
	_, err := db.Exec(query, username, ipAddress)
	if err != nil {
		log.Printf("Erro ao registrar falha de login: %v", err)
	}
}

// Função para obter o número de tentativas falhas de login para um IP específico
func getFailedLoginAttempts(username, ipAddress string) (int, error) {
	query := `SELECT COUNT(*) FROM failed_logins WHERE username = ? AND ip_address = ? AND timestamp > ?`
	timeLimit := time.Now().Add(-LockDuration).Format(time.RFC3339)
	var attempts int
	err := db.QueryRow(query, username, ipAddress, timeLimit).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("erro ao contar tentativas falhas: %v", err)
	}
	return attempts, nil
}

// Função para gerar uma mensagem de resposta personalizada de login
func GenerateLoginResponse(success bool, username string) string {
	if success {
		return fmt.Sprintf("Bem-vindo %s, você está autenticado com sucesso!", username)
	}
	return fmt.Sprintf("Falha ao tentar fazer login como %s. Verifique seu nome de usuário e senha.", username)
}

// Função para gerar uma resposta após bloqueio do IP
func GenerateBlockedResponse(ipAddress string) string {
	return fmt.Sprintf("O IP %s foi temporariamente bloqueado devido a múltiplas tentativas falhas de login. Tente novamente em alguns minutos.", ipAddress)
}

// Função para verificar se um IP está bloqueado
func IsIPBlocked(ipAddress string) bool {
	query := `SELECT COUNT(*) FROM failed_logins WHERE ip_address = ? AND timestamp > ?`
	timeLimit := time.Now().Add(-LockDuration).Format(time.RFC3339)
	var count int
	err := db.QueryRow(query, ipAddress, timeLimit).Scan(&count)
	if err != nil {
		log.Printf("Erro ao verificar se o IP está bloqueado: %v", err)
		return false
	}
	return count >= LoginAttemptLimit
}
