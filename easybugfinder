package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const maxThreads = 100

func pingHost(host string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", host)
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

func httpTest(host string) bool {
	url := "https://" + host + "/"
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("[HTTP] FAIL: Bad request:", err)
		return false
	}
	req.Header.Set("Host", host)
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (EasyBugFinder)")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[HTTP] FAIL:", err)
		return false
	}
	defer resp.Body.Close()
	fmt.Println("[HTTP] OK - Status:", resp.Status)
	return true
}

func scanHost(host string, port string, wg *sync.WaitGroup, progress chan<- struct{}, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	fmt.Println("\n🚀 Testing host:", host)
	pingOK := pingHost(host)
	tcpOK := tcpConnect(host, port)
	tlsOK := false
	httpOK := false
	if tcpOK {
		tlsOK = tlsHandshake(host, port)
		if tlsOK {
			httpOK = httpTest(host)
		}
	}
	fmt.Println("📝 SUMMARY for", host)
	fmt.Printf("PING: %v | TCP: %v | TLS: %v | HTTP: %v\n",
		boolToStatus(pingOK), boolToStatus(tcpOK), boolToStatus(tlsOK), boolToStatus(httpOK))
	<-sem
	progress <- struct{}{}
}

func boolToStatus(b bool) string {
	if b {
		return "OK"
	}
	return "FAIL"
}

func bulkScan(domains []string, port string) {
	var wg sync.WaitGroup
	progress := make(chan struct{}, len(domains))
	sem := make(chan struct{}, maxThreads)
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		wg.Add(1)
		go scanHost(d, port, &wg, progress, sem)
	}
	go showProgress(len(domains), progress)
	wg.Wait()
}

func cidrScan(cidr string, port string) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		fmt.Println("Invalid CIDR:", err)
		return
	}
	var wg sync.WaitGroup
	progress := make(chan struct{}, 1024)
	sem := make(chan struct{}, maxThreads)
	count := 0
	for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
		count++
		ipStr := ip.String()
		wg.Add(1)
		go scanHost(ipStr, port, &wg, progress, sem)
	}
	go showProgress(count, progress)
	wg.Wait()
}

func showProgress(total int, progress <-chan struct{}) {
	completed := 0
	for range progress {
		completed++
		fmt.Printf("\rProgress: %d/%d", completed, total)
	}
	fmt.Println("\n✅ All scans complete!")
}

func main() {
	for {
		fmt.Println("🌟 EASY BUGFINDER 🌟 (Made with TS Hacker)")
		fmt.Println("Select mode:")
		fmt.Println("1️⃣ Single domain scan")
		fmt.Println("2️⃣ Bulk domain scan")
		fmt.Println("3️⃣ CIDR range scan")
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
			var wg sync.WaitGroup
			progress := make(chan struct{}, 1)
			sem := make(chan struct{}, maxThreads)
			wg.Add(1)
			go scanHost(strings.TrimSpace(host), port, &wg, progress, sem)
			go showProgress(1, progress)
			wg.Wait()
		case 2:
			fmt.Println("Enter domains (comma-separated or multiple lines). End with empty line:")
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
}
