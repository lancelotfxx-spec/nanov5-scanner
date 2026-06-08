package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ANSI Escape Codes for colorized terminal output
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Gray   = "\033[90m"
)

// pingIP checks if the target host is alive using an ICMP Echo Request
func pingIP(ip string, timeout time.Duration) bool {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("SCAN"),
		},
	}

	bin, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	dst, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return false
	}

	if _, err := c.WriteTo(bin, dst); err != nil {
		return false
	}

	reply := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(timeout))

	n, _, err := c.ReadFrom(reply)
	if err != nil {
		return false
	}

	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
	if err != nil {
		return false
	}

	return rm.Type == ipv4.ICMPTypeEchoReply
}

// grabBanner attempts to read the banner service data from an open port
func grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "No response (Passive)"
	}

	banner := string(buffer[:n])
	banner = strings.ReplaceAll(banner, "\r", "")
	banner = strings.ReplaceAll(banner, "\n", " | ")
	
	if len(banner) > 80 {
		banner = banner[:77] + "..."
	}
	
	return strings.TrimSpace(banner)
}

// inc increments an IP address (used for CIDR generation)
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// parseCIDR generates a list of IP strings from a CIDR notation
func parseCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// parsePorts parses a comma-separated string of ports into an int slice
func parsePorts(portStr string) ([]int, error) {
	var ports []int
	parts := strings.Split(portStr, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port number: %s", p)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// resolveDomain converts a website domain name to an IP address string
func resolveDomain(domain string) (string, error) {
	// Strip protocol prefixes if accidentally entered by user
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0] // Extract only the host part

	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for domain")
}

// Task represents a combination of IP and Port to be scanned
type Task struct {
	IP   string
	Port int
}

// worker processes tasks from the channel concurrently
func worker(ctx context.Context, tasks <-chan Task, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range tasks {
		select {
		case <-ctx.Done():
			return
		default:
			address := fmt.Sprintf("%s:%d", task.IP, task.Port)
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err == nil {
				banner := grabBanner(conn)
				results <- fmt.Sprintf("%s[Open]%s %-20s -> %sBanner:%s %s", Green, Reset, address, Cyan, Reset, Gray+banner+Reset)
				conn.Close()
			}
		}
	}
}

func main() {
	// CLI Flags Definition
	target := flag.String("t", "127.0.0.1", "Target IP, Domain (e.g., target.com), or CIDR range")
	threads := flag.Int("c", 50, "Number of concurrent workers/threads")
	customPorts := flag.String("p", "", "Comma-separated custom ports to scan (e.g., 22,80,443)")

	// Custom Help Menu Configuration
	flag.Usage = func() {
		fmt.Print(Cyan)
		fmt.Println(`
 _   _                    __     _____ 


| \ | | ___  _ __   ___   \ \   / / ___|
|  \| |/ _ \| '_ \ / _ \   \ \ / /___ \ 
| |\  | (_) | | | | (_) |   \ V / ___) |
|_| \_|\___/|_| |_|\___/     \_/ |____/ 
                                       `)
		fmt.Print(Reset)
		fmt.Println("==================================================================")
		fmt.Printf("%s Nano V5 - Network Scanner & Banner Grabber%s\n", Yellow, Reset)
		fmt.Println("==================================================================")
		fmt.Println("Usage:")
		fmt.Println("  go run main.go [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  go run main.go -t google.com")
		fmt.Println("  go run main.go -t 192.168.1.1 -p 80,443,8080")
		fmt.Println("  go run main.go -t 192.168.1.0/24 -c 100")
	}

	flag.Parse()

	// Default ports list if -p is omitted
	portsToScan := []int{21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080}
	
	// Parse custom ports if provided
	if *customPorts != "" {
		var err error
		portsToScan, err = parsePorts(*customPorts)
		if err != nil {
			fmt.Printf("[%s!%s] Error parsing ports: %v\n", Red, Reset, err)
			return
		}
	}

	// Execution Banner Logo
	fmt.Print(Cyan)
	fmt.Println(`
 _   _                    __     _____ 


| \ | | ___  _ __   ___   \ \   / / ___|
|  \| |/ _ \| '_ \ / _ \   \ \ / /___ \ 
| |\  | (_) | | | | (_) |   \ V / ___) |
|_| \_|\___/|_| |_|\___/     \_/ |____/ 
                                       `)
	fmt.Print(Reset)
	fmt.Println("==================================================================")
	fmt.Printf("%s Creator: Nano V5%s\n", Yellow, Reset)
	fmt.Printf(" Target Input : %s\n", *target)
	fmt.Println("==================================================================")

	var targets []string

	// Check if input is CIDR block, Domain Name, or standard IP
	if strings.Contains(*target, "/") {
		fmt.Printf("[%s*%s] Parsing CIDR block...\n", Blue, Reset)
		var err error
		targets, err = parseCIDR(*target)
		if err != nil {
			fmt.Printf("[%s!%s] Invalid CIDR format: %v\n", Red, Reset, err)
			return
		}
		fmt.Printf("[%s+%s] Generated %d IP addresses from CIDR.\n", Green, Reset, len(targets))
	} else {
		// Check if input is a domain name by attempting lookup
		parsedIP := net.ParseIP(*target)
		if parsedIP == nil {
			fmt.Printf("[%s*%s] Resolving website domain target IP...\n", Blue, Reset)
			resolvedIP, err := resolveDomain(*target)
			if err != nil {
				fmt.Printf("[%s!%s] Failed to resolve domain %s: %v\n", Red, Reset, *target, err)
				return
			}
			fmt.Printf("[%s+%s] Domain resolved successfully: %s -> %s\n", Green, Reset, *target, resolvedIP)
			targets = []string{resolvedIP}
		} else {
			targets = []string{*target}
		}
	}

	// 1. Host Discovery
	fmt.Printf("[%s*%s] Discovering live hosts via ICMP Ping...\n", Blue, Reset)
	var liveHosts []string
	var pingWg sync.WaitGroup
	var mu sync.Mutex

	guard := make(chan struct{}, *threads)
	for _, ip := range targets {
		pingWg.Add(1)
		guard <- struct{}{}
		go func(host string) {
			defer pingWg.Done()
			defer func() { <-guard }()
			if pingIP(host, 1*time.Second) {
				mu.Lock()
				liveHosts = append(liveHosts, host)
				mu.Unlock()
				fmt.Printf("[%s+%s] Host is Alive: %s\n", Green, Reset, host)
			}
		}(ip)
	}
	pingWg.Wait()

	if len(liveHosts) == 0 {
		fmt.Printf("[%s!%s] No hosts responded to Ping. Proceeding to scan all IPs directly...\n", Yellow, Reset)
		liveHosts = targets
	} else {
		fmt.Printf("[%s*%s] Found %d active hosts. Starting port scan...\n", Blue, Reset)
	}

	// 2. Port Scanning & Banner Grabbing
	fmt.Printf("[%s*%s] Scanning %d ports using %d threads...\n", Blue, Reset, len(portsToScan), *threads)
	
	tasks := make(chan Task, 1000)
	results := make(chan string, 100)
	var scanWg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanWg.Add(*threads)
	for i := 0; i < *threads; i++ {
		go worker(ctx, tasks, results, &scanWg)
	}

	foundOpen := false
	go func() {
		for res := range results {
			fmt.Println(res)
			foundOpen = true
		}
	}()

	for _, ip := range liveHosts {
		for _, port := range portsToScan {
			tasks <- Task{IP: ip, Port: port}
		}
	}
	close(tasks)

	scanWg.Wait()
	close(results)

	time.Sleep(100 * time.Millisecond)

	if !foundOpen {
		fmt.Printf("[%s-%s] No targeted open ports were discovered.\n", Red, Reset)
	}
	fmt.Printf("\n[%s*%s] Network scan sequence completed.\n", Blue, Reset)
}

