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

. ├── cmd/ # Entrypoint da aplicação ├── internal/ │ ├── ssh/ # Servidor SSH falso │ ├── telnet/ # Servidor Telnet falso │ ├── web/ # Página de login fake │ ├── firewall/ # Regras de bloqueio │ └── logger/ # Registro de eventos ├── config/ # Arquivos de configuração ├── tests/ # Testes unitários ├── go.mod └── README.md


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

Execução

```
sudo ./honeypot --config ./config/config.yaml

``

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
