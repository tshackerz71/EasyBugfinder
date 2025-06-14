package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
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

type ScanResult struct {
	Host        string `json:"host"`
	Port        string `json:"port"`
	Ping        string `json:"ping"`
	TCP         string `json:"tcp"`
	TLS         string `json:"tls"`
	HTTPGet     string `json:"http_get"`
	CustomPorts []int  `json:"custom_ports"`
}

func showBanner() {
	fmt.Println("\033[1;36m")
	fmt.Println("███████╗ █████╗ ███████╗██╗   ██╗     ██████╗ ██╗   ██╗ ██████╗ ███████╗██████╗ ")
	fmt.Println("██╔════╝██╔══██╗██╔════╝██║   ██║    ██╔═══██╗██║   ██║██╔═══██╗██╔════╝██╔══██╗")
	fmt.Println("█████╗  ███████║███████╗██║   ██║    ██║   ██║██║   ██║██║   ██║█████╗  ██████╔╝")
	fmt.Println("██╔══╝  ██╔══██║╚════██║██║   ██║    ██║▄▄ ██║██║   ██║██║   ██║██╔══╝  ██╔══██╗")
	fmt.Println("██║     ██║  ██║███████║╚██████╔╝    ╚██████╔╝╚██████╔╝╚██████╔╝███████╗██║  ██║")
	fmt.Println("╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝      ╚══▀▀═╝  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝")
	fmt.Println("Made with ❤️ by TS Hacker")
	fmt.Println("\033[0m")
	fmt.Println()
}

func pingHost(host string) string {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", host)
	if err := cmd.Run(); err != nil {
		return "FAIL"
	}
	return "OK"
}

func tcpConnect(host, port string) string {
	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return "FAIL"
	}
	conn.Close()
	return "OK"
}

func tlsHandshake(host, port string) string {
	address := net.JoinHostPort(host, port)
	conf := &tls.Config{ServerName: host, InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, conf)
	if err != nil {
		return "FAIL"
	}
	conn.Close()
	return "OK"
}

func httpGetTest(host string) string {
	url := "https://" + host
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "FAIL"
	}
	resp.Body.Close()
	return "OK"
}

func scanHost(host, port string, customPorts []int, fullScan bool, wg *sync.WaitGroup, mu *sync.Mutex, output *[]ScanResult, progress chan<- int) {
	defer wg.Done()
	res := ScanResult{Host: host, Port: port}
	if fullScan {
		res.Ping = pingHost(host)
		res.TCP = tcpConnect(host, port)
		if res.TCP == "OK" {
			res.TLS = tlsHandshake(host, port)
		}
		res.HTTPGet = httpGetTest(host)
		for _, cp := range customPorts {
			if tcpConnect(host, fmt.Sprint(cp)) == "OK" {
				res.CustomPorts = append(res.CustomPorts, cp)
			}
		}
	}
	mu.Lock()
	*output = append(*output, res)
	mu.Unlock()
	progress <- 1
}

func saveResultsJSON(results []ScanResult) {
	f, _ := os.Create("scan_results.json")
	defer f.Close()
	json.NewEncoder(f).Encode(results)
	fmt.Println("Results saved to scan_results.json")
}

func showProgress(total int, progress <-chan int) {
	count := 0
	for range progress {
		count++
		fmt.Printf("Progress: %d/%d completed\r", count, total)
		if count == total {
			fmt.Println("\nAll scans done.")
			return
		}
	}
}

func main() {
	showBanner()
	for {
		fmt.Println("1. Single domain scan 2. Bulk 3. CIDR 4. Exit")
		var mode int
		fmt.Scanln(&mode)
		if mode == 4 {
			fmt.Println("Goodbye!")
			return
		}
		fmt.Println("Full scan (1) or selective (2)?")
		var scanType int
		fmt.Scanln(&scanType)
		fullScan := scanType == 1
		fmt.Println("Enter custom ports (comma, optional):")
		var cps string
		fmt.Scanln(&cps)
		var customPorts []int
		for _, p := range strings.Split(cps, ",") {
			if p != "" {
				var pi int
				fmt.Sscan(p, &pi)
				customPorts = append(customPorts, pi)
			}
		}
		var targets []string
		if mode == 1 {
			fmt.Println("Enter domain:")
			var d string
			fmt.Scanln(&d)
			targets = append(targets, d)
		} else if mode == 2 {
			fmt.Println("paste/comma/file?")
			var m string
			fmt.Scanln(&m)
			if m == "paste" {
				s := bufio.NewScanner(os.Stdin)
				for s.Scan() {
					l := s.Text()
					if l == "" { break }
					targets = append(targets, l)
				}
			} else if m == "comma" {
				var l string
				fmt.Scanln(&l)
				targets = strings.Split(l, ",")
			} else if m == "file" {
				var path string
				fmt.Scanln(&path)
				f, _ := os.Open(path)
				s := bufio.NewScanner(f)
				for s.Scan() { targets = append(targets, s.Text()) }
				f.Close()
			}
		} else if mode == 3 {
			fmt.Println("Enter CIDR:")
			var cidr string
			fmt.Scanln(&cidr)
			p, _ := netip.ParsePrefix(cidr)
			for ip := p.Masked().Addr(); p.Contains(ip); ip = ip.Next() {
				targets = append(targets, ip.String())
			}
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		var out []ScanResult
		progress := make(chan int)
		go showProgress(len(targets), progress)
		for _, t := range targets {
			wg.Add(1)
			go scanHost(strings.TrimSpace(t), "443", customPorts, fullScan, &wg, &mu, &out, progress)
		}
		wg.Wait()
		close(progress)
		saveResultsJSON(out)
	}
}
