package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type Result struct {
	Domain   string
	Alias    string
	IP       string
	DaysLeft int
}

func main() {
	// Check if domain argument is provided
	if len(os.Args) < 2 {
		fmt.Println("Usage: ssl_monitor '{\"domain.com\":[\"alias1.domain.com\",\"alias2.domain.com\"]}'")
		os.Exit(2)
	}

	// Parse domains JSON
	var domainAliases map[string][]string
	if err := json.Unmarshal([]byte(os.Args[1]), &domainAliases); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(2)
	}

	results := checkAllDomains(domainAliases)

	// Print results in the required format
	for _, r := range results {
		fmt.Printf("domain: %s, alias: %s, ip: %s, value: %d\n", 
			r.Domain, r.Alias, r.IP, r.DaysLeft)
	}
}

func checkAllDomains(domainAliases map[string][]string) []Result {
	var results []Result
	var mutex sync.Mutex
	var wg sync.WaitGroup

	for domain, aliases := range domainAliases {
		for _, alias := range aliases {
			// Get all IPs for this alias
			ips, err := net.LookupIP(alias)
			if err != nil {
				// Skip this alias if DNS lookup fails
				continue
			}

			// Check each IP
			for _, ip := range ips {
				ipStr := ip.String()
				
				// Skip IPv6 addresses
				if ip.To4() == nil {
					continue
				}
				
				wg.Add(1)
				go func(ip, domain, alias string) {
					defer wg.Done()
					daysLeft := checkCertificate(ip, domain)
					
					if daysLeft >= 0 {
						mutex.Lock()
						results = append(results, Result{
							Domain:   domain,
							Alias:    alias,
							IP:       ip,
							DaysLeft: daysLeft,
						})
						mutex.Unlock()
					}
				}(ipStr, domain, alias)
			}
		}
	}

	wg.Wait()
	return results
}

func checkCertificate(ip, domain string) int {
	// Set connection timeout
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	
	conf := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         domain,
	}

	// Connect with timeout
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", ip), conf)
	if err != nil {
		return -1 // Indicate error
	}
	defer conn.Close()

	// Get certificate details
	now := time.Now()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return -1 // No certificates
	}

	cert := certs[0] // Use the first certificate
	validDays := int(cert.NotAfter.Sub(now).Hours() / 24)
	
	return validDays
}