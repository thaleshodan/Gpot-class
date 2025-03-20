package main

import (
	"fmt"
	"log"
	"myhoneypot/internal/handlers"
	"net"
	"sync"
)

const (
	sshPort    = ":2222"
	telnetPort = ":23"
	ftpPort    = ":21"
)

func startServer(protocol, port string, handler func(net.Conn)) {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("[ERROR] Failed to start %s server on port %s: %v", protocol, port, err)
	}
	defer listener.Close()
	log.Printf("[INFO] %s honeypot listening on %s", protocol, port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ERROR] Connection error on %s: %v", protocol, err)
			continue
		}
		go handler(conn) // Lidar com a conexão em uma goroutine
	}
}

func main() {
	var wg sync.WaitGroup

	wg.Add(3)

	go func() {
		defer wg.Done()
		startServer("SSH", sshPort, handlers.HandleSSH)
	}()

	go func() {
		defer wg.Done()
		startServer("Telnet", telnetPort, handlers.HandleTelnet)
	}()

	go func() {
		defer wg.Done()
		startServer("FTP", ftpPort, handlers.HandleFTP)
	}()

	wg.Wait()
}
