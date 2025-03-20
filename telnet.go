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

	_ "github.com/mattn/go-sqlite3" // Para salvar logs em SQLite opcionalmente
	"yourproject/internal/logs"
)

const (
	telnetPort      = "0.0.0.0:2323"
	fakeUsername    = "admin"
	fakePassword    = "admin"
	bannerMessage   = "Unauthorized access is prohibited.\n"
	timeoutDuration = 120 * time.Second
)

var fakeCommandResponses = map[string]string{
	"whoami":          "admin",
	"uname -a":        "Linux honeypot 5.10.0-kali #1 SMP Debian 5.10.46-4kali2 x86_64 GNU/Linux",
	"ls":              "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  sbin  srv  tmp  usr  var",
	"pwd":             "/home/admin",
	"ifconfig":        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\ninet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255",
	"ps aux":          "USER       PID  %CPU %MEM    TIME+  COMMAND\nadmin      1342  0.1  0.5   20000   1024 ?        Ss   00:00   0:00 /bin/bash",
	"cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash",
	"ls /tmp":         "/tmp/.rootkit /tmp/backdoor /tmp/hacktool",
	"exit":            "Connection closed.\n",
}

var suspiciousCommands = []string{"nc", "wget", "curl", "nmap", "bash -i", "perl -e", "python -c", "netcat", "chmod +x"}

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

	conn.Write([]byte(bannerMessage))

	username, password := fakeLogin(conn)
	if username == "" || password == "" {
		logs.Warn(fmt.Sprintf("Failed login attempt from %s", clientAddr))
		logToFile(fmt.Sprintf("Failed login attempt from %s", clientAddr))
		saveToDatabase(clientAddr, "FAILED_LOGIN", "")
		return
	}

	logs.Info(fmt.Sprintf("Successful Telnet login from %s with user: %s", clientAddr, username))
	logToFile(fmt.Sprintf("Successful login from %s - Username: %s", clientAddr, username))
	saveToDatabase(clientAddr, "SUCCESSFUL_LOGIN", username)

	handleFakeShell(conn, clientAddr)
}

func fakeLogin(conn net.Conn) (string, string) {
	conn.Write([]byte("login: "))
	username := readLine(conn)

	conn.Write([]byte("Password: "))
	password := readLine(conn)

	if username == fakeUsername && password == fakePassword {
		conn.Write([]byte("\nWelcome to the system.\n"))
		return username, password
	}

	conn.Write([]byte("\nLogin incorrect.\n"))
	return "", ""
}

func handleFakeShell(conn net.Conn, clientAddr string) {
	conn.Write([]byte("$ "))

	conn.SetReadDeadline(time.Now().Add(timeoutDuration))

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())

		conn.SetReadDeadline(time.Now().Add(timeoutDuration))

		if command == "" {
			continue
		}

		logs.Info(fmt.Sprintf("Telnet command from %s: %s", clientAddr, command))
		logToFile(fmt.Sprintf("Telnet command from %s: %s", clientAddr, command))
		saveToDatabase(clientAddr, "COMMAND_EXECUTED", command)

		simulateCommandLatency(command)
		detectSuspiciousCommand(command, clientAddr)

		if response, exists := fakeCommandResponses[command]; exists {
			conn.Write([]byte(response + "\n"))
			if command == "exit" {
				return
			}
		} else {
			conn.Write([]byte(fmt.Sprintf("%s: command not found\n", command)))
		}

		conn.Write([]byte("$ "))
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Connection error from %s: %v", clientAddr, err)
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

func simulateCommandLatency(command string) {
	delay := map[string]time.Duration{
		"ls":        500 * time.Millisecond,
		"uname -a":  800 * time.Millisecond,
		"ifconfig":  1 * time.Second,
		"ps aux":    1 * time.Second,
	}
	if d, ok := delay[command]; ok {
		time.Sleep(d)
	} else {
		time.Sleep(time.Duration(rand.Intn(300)+100) * time.Millisecond)
	}
}

func detectSuspiciousCommand(command, clientAddr string) {
	for _, s := range suspiciousCommands {
		if strings.Contains(command, s) {
			alertMessage := fmt.Sprintf("ALERT! Possible attack from %s: %s", clientAddr, command)
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
