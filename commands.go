package handlers

import (
	"strings"
	"time"
)

// ProcessCommand recebe um comando do usuário e retorna uma resposta realista.
func ProcessCommand(cmd string) string {
	cmd = strings.TrimSpace(strings.ToLower(cmd))

	// Simula comportamento realista do Telnet/SSH
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
	case "exit":
		return "Session closed."

	// Comandos suspeitos (scanners, exploits)
	case "nmap -p- localhost", "hydra -L users.txt -P passwords.txt ssh://localhost":
		return "ALERT! Possible attack detected."

	// Comando falso para enganar invasores
	case "rm -rf /":
		time.Sleep(2 * time.Second)
		return "Permission denied."

	default:
		return "Command not found."
	}
}
