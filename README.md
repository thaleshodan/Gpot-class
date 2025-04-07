# Honeypot Avançado em Go

Honeypot modular e eficiente, desenvolvido em Go, focado em captura de comportamento malicioso e coleta de IOCs. Suporta conexões SSH e Telnet, simula login falso e possui sistema de firewall integrado.

---

## Visão Geral

Este honeypot foi projetado para ambientes de análise e monitoramento de ameaças. Ele captura credenciais, comandos e interações, oferecendo uma base sólida para análises automatizadas ou manuais.

---

## Funcionalidades

- Servidor **SSH** e **Telnet** falsos com logging completo
- Página de **login simulada** via interface web
- **Firewall embutido** com regras por IP e porta
- **Logs estruturados** (JSON) com suporte a exportação
- Arquitetura **modular**, fácil de estender e integrar

---

## Estrutura


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

## Requisitos

- Go 1.20+
- Linux ou Windows
- Acesso root (para portas privilegiadas ou firewall)

---

## Instalação

```bash
git clone https://github.com/thaleshodan/advanced-go-honeypot.git
cd advanced-go-honeypot
go build -o honeypot ./cmd

```

## Execução

```
sudo ./honeypot --config ./config/config.yaml

```

Parâmetros comuns:
Flag	Descrição
--config	Caminho do arquivo de configuração
--export-logs	Exporta logs estruturados
--debug	Verbosidade detalhada
--blocklist	Lista de IPs bloqueados
Exemplo de Log

{
  "timestamp": "2025-04-07T12:10:45Z",
  "source_ip": "192.168.1.101",
  "protocol": "ssh",
  "username": "admin",
  "password": "toor",
  "command": "uname -a",
  "status": "attempt"
}

Segurança

Use apenas em ambientes isolados. Este honeypot não deve ser executado em máquinas de produção. Preferencialmente rode em container, VM ou rede segregada.
Licença

MIT. Consulte o arquivo LICENSE.
Autor

Thales Shodan
Desenvolvedor de ferramentas defensivas e pesquisador em segurança ofensiva
github.com/thaleshodan
