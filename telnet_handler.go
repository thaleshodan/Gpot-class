package handlers

import (
	"net"
	"myhoneypot/logging"
)

func HandleTelnetConnection(conn net.Conn, logger *logging.Logger) {
	defer conn.Close()

	ip := conn.RemoteAddr().String()

	if logger.IsIPBanned(ip) {
		logger.Log(ip, "Conexão Telnet recusada (IP banido)", WARNING)
		return
	}

	logger.Log(ip, "Tentativa de login via Telnet", INFO)

	// Simulação de resposta falsa para enganar invasores
	conn.Write([]byte("Login: "))
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
	telnetPort      = "0.0.0.0:23"
	fakeUsername    = "admin"
	fakePassword    = "admin"
	timeoutSeconds  = 120
	telnetBanner    = "\r\nWelcome to the Telnet honeypot. Unauthorized access is prohibited.\r\n"
)

var fakeTelnetResponses = map[string]string{
	"ls":         "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
	"whoami":     "admin",
	"uname -a":   "Linux honeypot 5.15.0-58-generic x86_64 GNU/Linux",
	"id":         "uid=0(root) gid=0(root) groups=0(root)",
	"pwd":        "/home/admin",
	"cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin,,,:/home/admin:/bin/bash",
	"exit":       "Connection closed by remote host.",
}

var suspiciousTelnetCommands = []string{"hydra", "nmap", "telnet-brute", "wget", "curl", "nc", "chmod +x", "python -c", "perl -e"}

func StartTelnetServer() {
	listener, err := net.Listen("tcp", telnetPort)
	if err != nil {
		log.Fatalf("Failed to start Telnet server: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening for Telnet connections on %s...", telnetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept Telnet connection: %v", err)
			continue
		}

		go handleTelnetConnection(conn)
	}
}

func handleTelnetConnection(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	logs.Info(fmt.Sprintf("New Telnet connection from %s", clientAddr))

	conn.Write([]byte(telnetBanner))

	username, password := fakeTelnetLogin(conn)
	if username == "" || password == "" {
		logs.Warn(fmt.Sprintf("Failed Telnet login attempt from %s", clientAddr))
		logToFile(fmt.Sprintf("Failed login from %s", clientAddr))
		saveToDatabase(clientAddr, "FAILED_LOGIN", "")
		return
	}

	logs.Info(fmt.Sprintf("Successful Telnet login from %s with user: %s", clientAddr, username))
	logToFile(fmt.Sprintf("Successful login from %s - Username: %s", clientAddr, username))
	saveToDatabase(clientAddr, "SUCCESSFUL_LOGIN", username)

	handleFakeTelnetCommands(conn, clientAddr)
}

func fakeTelnetLogin(conn net.Conn) (string, string) {
	scanner := bufio.NewScanner(conn)

	conn.Write([]byte("login: "))
	scanner.Scan()
	username := scanner.Text()

	conn.Write([]byte("Password: "))
	scanner.Scan()
	password := scanner.Text()

	if username == fakeUsername && password == fakePassword {
		conn.Write([]byte("Welcome to Telnet!\r\n"))
		return username, password
	}

	conn.Write([]byte("Login incorrect.\r\n"))
	return "", ""
}

func handleFakeTelnetCommands(conn net.Conn, clientAddr string) {
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())

		if command == "" {
			continue
		}

		logs.Info(fmt.Sprintf("Telnet command from %s: %s", clientAddr, command))
		logToFile(fmt.Sprintf("Telnet command from %s: %s", clientAddr, command))
		saveToDatabase(clientAddr, "COMMAND_EXECUTED", command)

		detectSuspiciousCommand(command, clientAddr)

		if response, exists := fakeTelnetResponses[command]; exists {
			conn.Write([]byte(response + "\r\n"))
		} else {
			conn.Write([]byte("bash: " + command + ": command not found\r\n"))
		}

		conn.Write([]byte("admin@honeypot:~$ "))
	}
}

func logToFile(message string) {
	f, err := os.OpenFile("logs/telnet.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Error opening log file:", err)
		return
	}
	defer f.Close()

	logger := log.New(f, "", log.LstdFlags)
	logger.Println(message)
}

func detectSuspiciousCommand(command, clientAddr string) {
	for _, s := range suspiciousTelnetCommands {
		if strings.Contains(command, s) {
			alertMessage := fmt.Sprintf("ALERT! Possible Telnet attack from %s: %s", clientAddr, command)
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
