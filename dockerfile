# Usa uma imagem mínima do Golang
FROM golang:1.21-alpine AS builder

# Instalar dependências do sistema
RUN apk add --no-cache bash sqlite

# Criar diretório de trabalho
WORKDIR /app

# Copiar os arquivos do projeto
COPY go.mod go.sum ./
RUN go mod download

# Copiar código-fonte
COPY . .

# Compilar o binário final (static build para rodar sem dependências)
RUN go build -o honeypot ./cmd/server.go

# --------------------------
# Criar uma nova imagem mínima
FROM alpine:latest

# Instalar SQLite (para logs)
RUN apk add --no-cache sqlite

# Criar usuário não root para segurança
RUN addgroup -S honeypot && adduser -S honeypot -G honeypot
USER honeypot

# Criar diretório de trabalho
WORKDIR /home/honeypot

# Copiar o binário do servidor e arquivos de configuração
COPY --from=builder /app/honeypot /usr/local/bin/honeypot
COPY config/config.yaml ./config.yaml

# Expor portas que o honeypot irá escutar (SSH, Telnet, FTP)
EXPOSE 22 23 21

# Rodar o honeypot
CMD ["/usr/local/bin/honeypot"]
