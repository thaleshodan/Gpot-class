# Advanced Honeypot in Go

Modular and efficient honeypot, developed in Go, focused on capturing malicious behavior and collecting IOCs. It supports SSH and Telnet connections, simulates fake logins and has an integrated firewall system.

---

## Overview

This honeypot was designed for threat analysis and monitoring environments. It captures credentials, commands and interactions, providing a solid foundation for automated or manual analysis.

---
## Features

- Fake **SSH** and **Telnet** server with full logging
- Simulated **login** page via web interface
- **Built-in firewall** with rules by IP and port
- **Structured logs** (JSON) with export support
- **Modular** architecture, easy to extend and integrate

---

## Structure
```
.
├── cmd/                  # Ponto de entrada principal
│   └── server/           # Implementação do servidor
├── internal/
│   ├── auth/             # Lógica de autenticação fake
│   ├── fake/             # Implementações dos serviços falsos
│   │   ├── ssh/
│   │   ├── telnet/
│   │   └── web/
│   ├── firewall/         # Regras de bloqueio
│   ├── logger/           # Registro de eventos
│   └── models/           # Estruturas de dados compartilhadas
├── pkg/                  # Código que pode ser reutilizado externamente (opcional)
├── configs/             # Configurações (melhor nome que "config")
├── scripts/             # Scripts auxiliares (se necessário)
├── tests/               # Testes
├── go.mod
├── go.sum
├── Makefile             # Para automatizar tarefas (opcional)
└── README.md
````

---

## Requirements

- Go 1.20+
- Linux or Windows
- Root access (for privileged ports or firewall)

---

## Installation

```bash
git clone https://github.com/thaleshodan/advanced-go-honeypot.git
cd advanced-go-honeypot
go build -o honeypot ./cmd

```

## Execution

```
sudo ./honeypot --config ./config/config.yaml

```

Common parameters:
Flag Description
--config Configuration file path
--export-logs Export structured logs
--debug Verbose verbose
--blocklist List of blocked IPs
Example Log

{
"timestamp": "2025-04-07T12:10:45Z",
"source_ip": "192.168.1.101",
"protocol": "ssh",
"username": "admin",
"password": "toor",
"command": "uname -a",
"status": "attempt"
}
Security

Use only in isolated environments. This honeypot should not be run on production machines. Preferably run in a container, VM or segregated network.

License

MIT. See the LICENSE file.

Author

Thales Shodan
Defensive tool developer and offensive security researcher
github.com/thaleshodan
