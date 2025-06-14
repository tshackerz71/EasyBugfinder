package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

func pingHost(host string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", host) // For Linux/Mac
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
		ServerName:         host,
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

func scanHost(host string, port string) {
	fmt.Println("\nTesting host:", host)

	pingOK := pingHost(host)
	tcpOK := tcpConnect(host, port)
	tlsOK := false
	if tcpOK {
		tlsOK = tlsHandshake(host, port)
	}

	fmt.Println("SUMMARY for", host)
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
		fmt.Println("TLS HANDSHAKE: OK → ✅ Can test in tunnel app")
	} else {
		fmt.Println("TLS HANDSHAKE: FAIL")
	}
}

func bulkScan(domains []string, port string) {
	for _, d := range domains {
		scanHost(strings.TrimSpace(d), port)
	}
}

func cidrScan(cidr string, port string) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		fmt.Println("Invalid CIDR:", err)
		return
	}
	for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
		scanHost(ip.String(), port)
	}
}

func main() {
	fmt.Println("🌟 EASY BUGFINDER 🌟")
	fmt.Println("Select mode:")
	fmt.Println("1. Single domain scan")
	fmt.Println("2. Bulk domain scan")
	fmt.Println("3. CIDR range scan")
	fmt.Print("Choice: ")

	var choice int
	fmt.Scanln(&choice)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter port (default 443): ")
	portInput, _ := reader.ReadString('\n')
	port := strings.TrimSpace(portInput)
	if port == "" {
		port = "443"
	}

	switch choice {
	case 1:
		fmt.Print("Enter domain: ")
		host, _ := reader.ReadString('\n')
		scanHost(strings.TrimSpace(host), port)
	case 2:
		fmt.Println("Enter domains (comma-separated OR multiple lines). End with empty line:")
		var domains []string
		for {
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			if strings.Contains(line, ",") {
				domains = append(domains, strings.Split(line, ",")...)
			} else {
				domains = append(domains, line)
			}
		}
		bulkScan(domains, port)
	case 3:
		fmt.Print("Enter CIDR (e.g. 192.168.1.0/30): ")
		cidr, _ := reader.ReadString('\n')
		cidrScan(strings.TrimSpace(cidr), port)
	default:
		fmt.Println("Invalid choice.")
	}
}
