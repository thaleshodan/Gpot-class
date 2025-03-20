package handlers

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// FakeShell inicia uma sessão simulada de terminal para enganar invasores.
func FakeShell(conn net.Conn) {
	defer conn.Close()

	username := "admin"
	hostname := "server01"
	prompt := fmt.Sprintf("%s@%s:~$ ", username, hostname)
	history := []string{}

	// Mensagem inicial
	conn.Write([]byte("Welcome to Ubuntu 22.04 LTS\n"))
	conn.Write([]byte("Last login: " + time.Now().Format("Mon Jan 2 15:04:05 2006") + " from 192.168.1.100\n"))

	scanner := bufio.NewScanner(conn)
	for {
		// Exibe o prompt
		conn.Write([]byte(prompt))

		// Lê entrada do usuário
		if !scanner.Scan() {
			break
		}
		command := strings.TrimSpace(scanner.Text())
		history = append(history, command)

		// Registra a atividade do invasor
		logCommand(conn.RemoteAddr().String(), command)

		// Simula autocomplete (se pressionar "Tab")
		if command == "" {
			continue
		}
		if command == "history" {
			conn.Write([]byte(strings.Join(history, "\n") + "\n"))
			continue
		}

		// Processa o comando e retorna resposta
		response := ProcessCommand(command)
		conn.Write([]byte(response + "\n"))

		// Simula tempo de execução para comandos pesados
		simulateExecutionTime(command)

		// Simula logout ao digitar "exit"
		if command == "exit" {
			conn.Write([]byte("Connection closed.\n"))
			break
		}
	}
}

// logCommand registra os comandos do invasor
func logCommand(ip, command string) {
	logEntry := fmt.Sprintf("[%s] %s executed: %s\n", time.Now().Format("2006-01-02 15:04:05"), ip, command)
	fmt.Println(logEntry) // Pode ser salvo em arquivo também
}

// simulateExecutionTime adiciona delays para comandos pesados
func simulateExecutionTime(cmd string) {
	heavyCommands := map[string]time.Duration{
		"find / -perm -4000":    5 * time.Second,
		"ls -lah /":             2 * time.Second,
		"cat /etc/passwd":       1 * time.Second,
		"sudo -l":               3 * time.Second,
		"netstat -tulnp":        2 * time.Second,
		"ss -tulnp":             2 * time.Second,
		"w":                     1 * time.Second,
		"last":                  2 * time.Second,
		"history":               1 * time.Second,
	}
	if delay, exists := heavyCommands[cmd]; exists {
		time.Sleep(delay)
	}
}

// ProcessCommand simula respostas realistas para comandos de hackers
func ProcessCommand(cmd string) string {
	cmd = strings.TrimSpace(strings.ToLower(cmd))

	// Respostas falsas realistas
	switch cmd {
	case "ls", "dir":
		return "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
	case "pwd":
		return "/home/admin"
	case "whoami":
		return "admin"
	case "uname -a":
		return "Linux server01 5.15.0-84-generic #93-Ubuntu SMP x86_64 GNU/Linux"
	case "uptime":
		return "12:34:56 up 3 days,  4:55,  1 user,  load average: 0.10, 0.05, 0.01"
	case "ps aux":
		return "PID   USER      COMMAND\n1     root      /sbin/init\n2023  admin     /bin/bash"
	case "cat /etc/passwd":
		return "root:x:0:0:root:/root:/bin/bash\nadmin:x:1001:1001::/home/admin:/bin/bash"
	case "cat /etc/shadow":
		return "Permission denied"
	case "find / -perm -4000":
		return "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/chsh\n/usr/bin/newgrp"
	case "sudo -l":
		return "[sudo] password for admin: \nSorry, user admin may not run sudo on this system."
	case "su", "sudo su":
		return "Password: \nAuthentication failure"
	case "netstat -tulnp", "ss -tulnp":
		return "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n" +
			"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd\n" +
			"tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      5678/mysqld"
	case "w":
		return "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n" +
			"admin    pts/0    192.168.1.100    12:00    00:12   0.05s  0.05s -bash"
	case "last":
		return "admin    pts/0    192.168.1.100    Mon Mar 18 12:00 - 12:30  (00:30)\n" +
			"admin    pts/1    192.168.1.105    Sun Mar 17 10:45 - 11:10  (00:25)"
	case "exit":
		return "Session closed."
	default:
		return "Command not found."
	}
}
