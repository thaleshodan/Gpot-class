package logging

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3" // Driver SQLite
)

// LogLevel define os níveis de log
type LogLevel string

const (
	INFO     LogLevel = "INFO"
	WARNING  LogLevel = "WARNING"
	ERROR    LogLevel = "ERROR"
	CRITICAL LogLevel = "CRITICAL"
)

// LogEntry representa um evento de log
type LogEntry struct {
	Timestamp string   `json:"timestamp"`
	IP        string   `json:"ip"`
	Event     string   `json:"event"`
	Level     LogLevel `json:"level"`
}

// Logger gerencia logs no sistema
type Logger struct {
	logFile *os.File
	db      *sql.DB
}

// NewLogger cria um novo logger
func NewLogger(logPath, dbPath string) (*Logger, error) {
	// Criar arquivo de log rotativo
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("erro ao abrir arquivo de log: %v", err)
	}

	// Conectar ao banco de dados SQLite
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("erro ao conectar ao banco de dados: %v", err)
	}

	// Criar tabela de logs se não existir
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT,
			ip TEXT,
			event TEXT,
			level TEXT
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar tabela de logs: %v", err)
	}

	return &Logger{logFile: file, db: db}, nil
}

// Log registra eventos com nível de severidade
func (l *Logger) Log(ip, event string, level LogLevel) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Criar entrada de log
	entry := LogEntry{
		Timestamp: timestamp,
		IP:        ip,
		Event:     event,
		Level:     level,
	}

	// Transformar em JSON para logs estruturados
	jsonLog, _ := json.Marshal(entry)

	// Escrever no console
	fmt.Println(string(jsonLog))

	// Escrever no arquivo
	_, _ = l.logFile.WriteString(string(jsonLog) + "\n")

	// Inserir no banco de dados
	_, _ = l.db.Exec("INSERT INTO logs (timestamp, ip, event, level) VALUES (?, ?, ?, ?)", timestamp, ip, event, level)
}

// Close fecha os recursos do logger
func (l *Logger) Close() {
	l.logFile.Close()
	l.db.Close()
}

// BanIP adiciona um IP à lista de banidos
func (l *Logger) BanIP(ip string) {
	_, _ = l.db.Exec("INSERT INTO banned_ips (ip) VALUES (?)", ip)
	log.Printf("⚠️ IP BANIDO: %s\n", ip)
}

// IsIPBanned verifica se um IP está banido
func (l *Logger) IsIPBanned(ip string) bool {
	var count int
	_ = l.db.QueryRow("SELECT COUNT(*) FROM banned_ips WHERE ip = ?", ip).Scan(&count)
	return count > 0
}
