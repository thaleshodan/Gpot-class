
  package cmd

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3" // Para salvar logs no SQLite
	"yourproject/internal/logs"
)

const (
	ftpPort        = "0.0.0.0:21"
	fakeUsername   = "admin"
	fakePassword   = "admin"
	timeoutSeconds = 120
)

var fakeFTPResponses = map[string]string{
	"USER admin":  "331 Password required for admin.",
	"PASS admin":  "230 User logged in, proceed.",
	"PWD":         `257 "/" is the current directory`,
	"LIST":        "150 Opening ASCII mode data connection for file list.\ndrwxr-xr-x    2 admin    admin        4096 Mar 20 12:00 files\ndrwxr-xr-x    2 admin    admin        4096 Mar 20 12:01 logs",
	"MKD test":    "257 \"test\" directory created.",
	"DELE file1":  "550 Permission denied.",
	"STOR backdoor": "550 Permission denied.",
	"RETR secret": "550 File not found.",
	"QUIT":        "221 Goodbye.",
}

var suspiciousFTPCommands = []string{"HYDRA", "BRUTE", "nc", "wget", "curl", "netcat", "chmod", "perl -e", "python -c"}

func StartFTPServer() {
	listener, err := net.Listen("tcp", ftpPort)
	if err != nil {
		log.Fatalf("Failed to start FTP server: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening for FTP connections on %s...", ftpPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept FTP connection: %v", err)
			continue
		}

		go handleFTPConnection(conn)
	}
}

func handleFTPConnection(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	logs.Info(fmt.Sprintf("New FTP connection from %s", clientAddr))

	conn.Write([]byte("220 FTP Server Ready\r\n"))

	username, password := fakeFTPLogin(conn)
	if username == "" || password == "" {
		logs.Warn(fmt.Sprintf("Failed FTP login attempt from %s", clientAddr))
		logToFile(fmt.Sprintf("Failed login from %s", clientAddr))
		saveToDatabase(clientAddr, "FAILED_LOGIN", "")
		return
	}

	logs.Info(fmt.Sprintf("Successful FTP login from %s with user: %s", clientAddr, username))
	logToFile(fmt.Sprintf("Successful login from %s - Username: %s", clientAddr, username))
	saveToDatabase(clientAddr, "SUCCESSFUL_LOGIN", username)

	handleFakeFTPCommands(conn, clientAddr)
}

func fakeFTPLogin(conn net.Conn) (string, string) {
	conn.Write([]byte("331 Username required.\r\n"))
	username := readLine(conn)

	conn.Write([]byte("331 Password required.\r\n"))
	password := readLine(conn)

	if username == fakeUsername && password == fakePassword {
		conn.Write([]byte("230 User logged in, proceed.\r\n"))
		return username, password
	}

	conn.Write([]byte("530 Login incorrect.\r\n"))
	return "", ""
}

func handleFakeFTPCommands(conn net.Conn, clientAddr string) {
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())

		if command == "" {
			continue
		}

		logs.Info(fmt.Sprintf("FTP command from %s: %s", clientAddr, command))
		logToFile(fmt.Sprintf("FTP command from %s: %s", clientAddr, command))
		saveToDatabase(clientAddr, "COMMAND_EXECUTED", command)

		simulateCommandLatency(command)
		detectSuspiciousCommand(command, clientAddr)

		if response, exists := fakeFTPResponses[command]; exists {
			conn.Write([]byte(response + "\r\n"))
			if command == "QUIT" {
				return
			}
		} else {
			conn.Write([]byte("500 Unknown command.\r\n"))
		}
	}
}

func logToFile(message string) {
	f, err := os.OpenFile("logs/ftp.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Error opening log file:", err)
		return
	}
	defer f.Close()

	logger := log.New(f, "", log.LstdFlags)
	logger.Println(message)
}

func simulateCommandLatency(command string) {
	delay := map[string]time.Duration{
		"LIST":  700 * time.Millisecond,
		"PWD":   300 * time.Millisecond,
		"MKD":   800 * time.Millisecond,
		"STOR":  1 * time.Second,
		"RETR":  1 * time.Second,
	}
	if d, ok := delay[command]; ok {
		time.Sleep(d)
	} else {
		time.Sleep(time.Duration(rand.Intn(300)+100) * time.Millisecond)
	}
}

func detectSuspiciousCommand(command, clientAddr string) {
	for _, s := range suspiciousFTPCommands {
		if strings.Contains(command, s) {
			alertMessage := fmt.Sprintf("ALERT! Possible FTP attack from %s: %s", clientAddr, command)
			logs.Warn(alertMessage)
			logToFile(alertMessage)
			saveToDatabase(clientAddr, "SUSPICIOUS_COMMAND", command)
			blockSuspiciousIP(clientAddr)
		}
	}
}

func blockSuspiciousIP(ip string) {
	cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		logs.Warn(fmt.Sprintf("Failed to block IP %s: %v", ip, err))
		logToFile(fmt.Sprintf("Failed to block IP %s: %v", ip, err))
	} else {
		logs.Info(fmt.Sprintf("Blocked suspicious IP: %s", ip))
		logToFile(fmt.Sprintf("Blocked suspicious IP: %s", ip))
	}
}

func saveToDatabase(ip, event, detail string) {
	db, err := sql.Open("sqlite3", "honeypot.db")
	if err != nil {
		log.Printf("Database error: %v", err)
		return
	}
	defer db.Close()

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, ip TEXT, event TEXT, detail TEXT)")
	if err != nil {
		log.Printf("Failed to create table: %v", err)
		return
	}

	_, err = db.Exec("INSERT INTO logs (ip, event, detail) VALUES (?, ?, ?)", ip, event, detail)
	if err != nil {
		log.Printf("Failed to insert log: %v", err)
	}
}

func readLine(conn net.Conn) string {
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}
