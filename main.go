package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"time"
)

func pingHost(host string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", host) // For Linux/Mac
	// For Windows, use: cmd := exec.Command("ping", "-n", "1", host)
	err := cmd.Run()
	if err != nil {
		fmt.Println("[PING] FAIL:", err)
		return false
	}
	fmt.Println("[PING] OK")
	return true
}

func tcpConnect(host string, port string) bool {
	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		fmt.Println("[TCP] FAIL:", err)
		return false
	}
	fmt.Println("[TCP] OK")
	conn.Close()
	return true
}

func tlsHandshake(host string, port string) bool {
	address := net.JoinHostPort(host, port)
	conf := &tls.Config{
		ServerName: host,
		InsecureSkipVerify: true,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, conf)
	if err != nil {
		fmt.Println("[TLS] FAIL:", err)
		return false
	}
	fmt.Println("[TLS] OK")
	conn.Close()
	return true
}

func main() {
	host := "portal.facebook.com"
	port := "443"

	fmt.Println("Testing host:", host)

	pingOK := pingHost(host)
	tcpOK := tcpConnect(host, port)
	tlsOK := false
	if tcpOK {
		tlsOK = tlsHandshake(host, port)
	}

	fmt.Println("\nSUMMARY:")
	if pingOK {
		fmt.Println("PING: OK")
	} else {
		fmt.Println("PING: FAIL")
	}

	if tcpOK {
		fmt.Println("TCP CONNECT:", port, "OK")
	} else {
		fmt.Println("TCP CONNECT:", port, "FAIL")
	}

	if tlsOK {
		fmt.Println("TLS HANDSHAKE: OK")
		fmt.Println("✅ This SNI can be tested in your tunnel app")
	} else {
		fmt.Println("TLS HANDSHAKE: FAIL")
	}
}
