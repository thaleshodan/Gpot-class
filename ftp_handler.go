package handlers

import (
	"net"
	"myhoneypot/logging"
)

func HandleFTPConnection(conn net.Conn, logger *logging.Logger) {
	defer conn.Close()

	ip := conn.RemoteAddr().String()

	if logger.IsIPBanned(ip) {
		logger.Log(ip, "Conexão FTP recusada (IP banido)", WARNING)
		return
	}

	logger.Log(ip, "Tentativa de login via FTP", INFO)

	conn.Write([]byte("220 Fake FTP Server Ready\r\n"))
}

package cmd

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"yourproject/internal/logs"
)

const (
	ftpPort        = "0.0.0.0:21"
	fakeUsername   = "admin"
	fakePassword   = "admin"
	timeoutSeconds = 120
)

var fakeFTPResponses = map[string]string{
	"USER admin": "331 User admin okay, need password.",
	"PASS admin": "230 Login successful.",
	"SYST":       "215 UNIX Type: L8",
	"PWD":        `257 "/" is the current directory`,
	"LIST":       "drwxr-xr-x  5 root root  4096 Mar 20 12:00 home\n-rw-r--r--  1 root root  1234 Mar 20 12:05 README.txt",
	"QUIT":       "221 Goodbye.",
}

var suspiciousFTPCommands = []string{"hydra", "nmap", "ftp-brute", "wget", "curl", "nc", "chmod +x", "python -c", "perl -e"}

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

	conn.Write([]byte("220 FTP Server ready.\r\n"))

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
	scanner := bufio.NewScanner(conn)

	conn.Write([]byte("USER "))
	scanner.Scan()
	username := scanner.Text()

	conn.Write([]byte("PASS "))
	scanner.Scan()
	password := scanner.Text()

	if username == "admin" && password == "admin" {
		conn.Write([]byte("230 Login successful.\r\n"))
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

		detectSuspiciousCommand(command, clientAddr)

		if response, exists := fakeFTPResponses[command]; exists {
			conn.Write([]byte(response + "\r\n"))
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
