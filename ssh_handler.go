package handlers

import (
	"net"
	"myhoneypot/logging"
)

func HandleSSHConnection(conn net.Conn, logger *logging.Logger) {
	defer conn.Close()

	ip := conn.RemoteAddr().String()

	// Verificar se o IP já está banido
	if logger.IsIPBanned(ip) {
		logger.Log(ip, "Conexão SSH recusada (IP banido)", WARNING)
		return
	}

	// Logando tentativa de conexão
	logger.Log(ip, "Tentativa de login via SSH", INFO)

	// Lógica do honeypot...
}

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
	sshPort        = "0.0.0.0:22"
	fakeUsername   = "admin"
	fakePassword   = "admin"
	timeoutSeconds = 120
)

var fakeSSHResponses = map[string]string{
	"ls":         "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
	"whoami":     "admin",
	"uname -a":   "Linux honeypot 5.15.0-58-generic x86_64 GNU/Linux",
	"id":         "uid=0(root) gid=0(root) groups=0(root)",
	"pwd":        "/home/admin",
	"cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin,,,:/home/admin:/bin/bash",
	"exit":       "Connection closed by remote host.",
}

var suspiciousSSHCommands = []string{"hydra", "nmap", "metasploit", "msfconsole", "netcat", "nc", "wget", "curl", "chmod +x", "python -c", "perl -e"}

func StartSSHServer() {
	listener, err := net.Listen("tcp", sshPort)
	if err != nil {
		log.Fatalf("Failed to start SSH server: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening for SSH connections on %s...", sshPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept SSH connection: %v", err)
			continue
		}

		go handleSSHConnection(conn)
	}
}

func handleSSHConnection(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	logs.Info(fmt.Sprintf("New SSH connection from %s", clientAddr))

	conn.Write([]byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"))

	username, password := fakeSSHLogin(conn)
	if username == "" || password == "" {
		logs.Warn(fmt.Sprintf("Failed SSH login attempt from %s", clientAddr))
		logToFile(fmt.Sprintf("Failed login from %s", clientAddr))
		saveToDatabase(clientAddr, "FAILED_LOGIN", "")
		return
	}

	logs.Info(fmt.Sprintf("Successful SSH login from %s with user: %s", clientAddr, username))
	logToFile(fmt.Sprintf("Successful login from %s - Username: %s", clientAddr, username))
	saveToDatabase(clientAddr, "SUCCESSFUL_LOGIN", username)

	handleFakeSSHCommands(conn, clientAddr)
}

func fakeSSHLogin(conn net.Conn) (string, string) {
	conn.Write([]byte("login as: "))
	username := readLine(conn)

	conn.Write([]byte(username + "@honeypot's password: "))
	password := readLine(conn)

	if username == fakeUsername && password == fakePassword {
		conn.Write([]byte("Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.15.0-58-generic x86_64)\r\n\n"))
		conn.Write([]byte(username + "@honeypot:~$ "))
		return username, password
	}

	conn.Write([]byte("Permission denied, please try again.\r\n"))
	return "", ""
}

func handleFakeSSHCommands(conn net.Conn, clientAddr string) {
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())

		if command == "" {
			continue
		}

		logs.Info(fmt.Sprintf("SSH command from %s: %s", clientAddr, command))
		logToFile(fmt.Sprintf("SSH command from %s: %s", clientAddr, command))
		saveToDatabase(clientAddr, "COMMAND_EXECUTED", command)

		simulateCommandLatency(command)
		detectSuspiciousCommand(command, clientAddr)

		if response, exists := fakeSSHResponses[command]; exists {
			conn.Write([]byte(response + "\r\n"))
		} else {
			conn.Write([]byte("bash: " + command + ": command not found\r\n"))
		}

		conn.Write([]byte("admin@honeypot:~$ "))
	}
}

func logToFile(message string) {
	f, err := os.OpenFile("logs/ssh.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
		"ls":       500 * time.Millisecond,
		"whoami":   300 * time.Millisecond,
		"uname -a": 1 * time.Second,
		"id":       400 * time.Millisecond,
	}
	if d, ok := delay[command]; ok {
		time.Sleep(d)
	} else {
		time.Sleep(time.Duration(rand.Intn(300)+100) * time.Millisecond)
	}
}

func detectSuspiciousCommand(command, clientAddr string) {
	for _, s := range suspiciousSSHCommands {
		if strings.Contains(command, s) {
			alertMessage := fmt.Sprintf("ALERT! Possible SSH attack from %s: %s", clientAddr, command)
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


