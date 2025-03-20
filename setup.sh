#!/bin/bash

# Script de configuração para o Honeypot
# Este script é responsável por configurar o ambiente para o honeypot, instalando dependências,
# configurando firewall, banco de dados de logs e configurando o Docker.

set -e  # Faz com que o script pare imediatamente em caso de erro
set -u  # Tratar variáveis não definidas como erro
set -o pipefail  # Faz com que falhas em pipes causem erro

# Arquivo de log
LOG_FILE="honeypot_setup.log"

# Função para registrar logs
log() {
    local MESSAGE=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $MESSAGE" | tee -a "$LOG_FILE"
}

# Função para verificar se a distribuição do sistema é compatível
check_system_compatibility() {
    DISTRO=$(lsb_release -si)
    if [[ "$DISTRO" != "Ubuntu" && "$DISTRO" != "Debian" ]]; then
        log "Este script foi projetado para funcionar apenas com Ubuntu ou Debian."
        exit 1
    fi
}

# Verifica se o script está sendo executado como root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "Este script precisa ser executado como root!"
        exit 1
    fi
}

# Função para instalar pacotes se não estiverem instalados
install_package_if_needed() {
    local PACKAGE=$1
    if ! command -v "$PACKAGE" &>/dev/null; then
        log "Instalando pacote: $PACKAGE"
        apt-get install -y "$PACKAGE" || { log "Falha ao instalar o pacote: $PACKAGE"; exit 1; }
    else
        log "Pacote $PACKAGE já está instalado."
    fi
}

# Função para verificar a versão de pacotes críticos
check_package_version() {
    local PACKAGE=$1
    local MIN_VERSION=$2
    INSTALLED_VERSION=$(dpkg-query -W -f='${Version}' "$PACKAGE")
    
    if dpkg --compare-versions "$INSTALLED_VERSION" lt "$MIN_VERSION"; then
        log "A versão de $PACKAGE ($INSTALLED_VERSION) é inferior à versão mínima recomendada ($MIN_VERSION). Atualizando..."
        apt-get install --only-upgrade "$PACKAGE" || { log "Falha ao atualizar $PACKAGE"; exit 1; }
    else
        log "A versão do pacote $PACKAGE ($INSTALLED_VERSION) está adequada."
    fi
}

# Função para instalar dependências do sistema
install_dependencies() {
    log "Iniciando a instalação das dependências..."
    
    apt-get update && apt-get upgrade -y || { log "Falha ao atualizar pacotes"; exit 1; }

    # Instalação de pacotes essenciais
    for package in git curl make build-essential golang ufw sqlite3; do
        install_package_if_needed "$package"
    done

    # Verifica e instala a versão mais recente do Docker
    if ! command -v docker &>/dev/null; then
        log "Instalando Docker..."
        curl -fsSL https://get.docker.com | sh || { log "Falha ao instalar Docker"; exit 1; }
    else
        check_package_version docker "20.10"
    fi

    # Instala o ClamAV, se não estiver instalado
    install_package_if_needed clamav clamav-daemon

    log "Dependências instaladas com sucesso."
}

# Função para configurar variáveis de ambiente do Go
configure_go_env() {
    log "Configurando variáveis de ambiente para Go..."

    # Adiciona variáveis de ambiente no ~/.bashrc
    if ! grep -q "GOPATH" ~/.bashrc; then
        echo "export GOPATH=\$HOME/go" >> ~/.bashrc
        echo "export GOROOT=/usr/local/go" >> ~/.bashrc
        echo "export PATH=\$GOROOT/bin:\$GOPATH/bin:\$PATH" >> ~/.bashrc
        log "Variáveis de ambiente do Go adicionadas ao ~/.bashrc"
    else
        log "Variáveis de ambiente do Go já configuradas."
    fi

    source ~/.bashrc
}

# Função para configurar o firewall usando UFW
configure_firewall() {
    log "Configurando o firewall (UFW)..."
    
    ufw allow 22/tcp  # Porta SSH
    ufw allow 23/tcp  # Porta Telnet
    ufw allow 21/tcp  # Porta FTP
    ufw allow 80/tcp  # Porta HTTP
    ufw allow 443/tcp # Porta HTTPS

    # Ativa o firewall
    ufw enable || { log "Falha ao ativar o firewall"; exit 1; }

    log "Firewall configurado com sucesso."
}

# Função para configurar o banco de dados de logs
configure_logs_db() {
    log "Configurando o banco de dados de logs..."

    local DB_PATH="/var/lib/honeypot/logs.db"

    if [ ! -f "$DB_PATH" ]; then
        log "Banco de dados de logs não encontrado. Criando novo banco..."
        sqlite3 "$DB_PATH" "CREATE TABLE logs (id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, event TEXT);" || { log "Falha ao criar o banco de dados"; exit 1; }
    else
        log "Banco de dados de logs já existe."
    fi
}

# Função para configurar o Docker e o container do honeypot
configure_docker() {
    log "Configurando o Docker e o container do honeypot..."

    # Certifica-se de que o Docker está em execução
    systemctl start docker
    systemctl enable docker

    # Verifica se o container do honeypot existe, se não, cria
    if ! docker ps -a | grep -q "honeypot"; then
        log "Criando e iniciando o container do honeypot..."
        docker build -t honeypot . || { log "Falha ao construir a imagem do Docker"; exit 1; }
        docker run -d --name honeypot -p 22:22 -p 23:23 -p 21:21 -p 80:80 -p 443:443 honeypot || { log "Falha ao rodar o container"; exit 1; }
    else
        log "O container do honeypot já está em execução."
    fi
}

# Função para configurar variáveis de ambiente do Go
check_dependencies() {
    log "Verificando se todas as dependências estão corretas..."

    if ! command -v go &>/dev/null; then
        log "Go não encontrado. Instalando Go..."
        install_package_if_needed golang
    fi

    log "Todas as dependências verificadas com sucesso."
}

# Função principal que chama todas as etapas
main() {
    check_root
    check_system_compatibility
    install_dependencies
    check_dependencies
    configure_go_env
    configure_firewall
    configure_logs_db
    configure_docker

    log "Configuração do honeypot concluída com sucesso!"
    log "Você pode verificar os logs detalhados no arquivo: $LOG_FILE"
}

# Executa a função principal
main
