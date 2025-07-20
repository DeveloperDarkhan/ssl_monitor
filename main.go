package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type Result struct {
	IP       string
	Domain   string
	Message  string
	IsOK     bool
	ExitCode int
}

func main() {
	// Parse command line arguments
	var criticalDays, warningDays int
	flag.IntVar(&criticalDays, "c", 14, "Critical threshold in days before expiration")
	flag.IntVar(&warningDays, "w", 30, "Warning threshold in days before expiration")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage: ssl_monitor '{\"domain.com\":[\"alias1.domain.com\",\"alias2.domain.com\"]}' -c [critical days] -w [warning days]")
		os.Exit(2)
	}

	// Parse domains JSON
	var domainAliases map[string][]string
	if err := json.Unmarshal([]byte(flag.Arg(0)), &domainAliases); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(2)
	}

	now := time.Now()
	results := checkAllDomains(domainAliases, criticalDays, warningDays)

	// Format output
	ok := "Good news: ["
	bad := "Bad news: ["
	exitCode := 0

	for _, r := range results {
		if r.IsOK {
			ok += r.Message
		} else {
			bad += r.Message
			if r.ExitCode > exitCode {
				exitCode = r.ExitCode
			}
		}
	}

	ok += "] "
	bad += "]"

	fmt.Println(now.Format("2006-01-02 15:04:05"), ok, bad)
	os.Exit(exitCode)
}

func checkAllDomains(domainAliases map[string][]string, criticalDays, warningDays int) []Result {
	var results []Result
	var mutex sync.Mutex
	var wg sync.WaitGroup

	for domain, aliases := range domainAliases {
		// Get all IPs for this domain's aliases
		ipMap := make(map[string]bool)
		for _, alias := range aliases {
			ips, err := net.LookupIP(alias)
			if err != nil {
				mutex.Lock()
				results = append(results, Result{
					IP:       "",
					Domain:   alias,
					Message:  fmt.Sprintf(" # DNS lookup failed for %s: %v ", alias, err),
					IsOK:     false,
					ExitCode: 2,
				})
				mutex.Unlock()
				continue
			}

			for _, ip := range ips {
				ipStr := ip.String()
				ipMap[ipStr] = true
			}
		}

		// Check each IP in parallel
		for ip := range ipMap {
			wg.Add(1)
			go func(ip, domain string) {
				defer wg.Done()
				result := checkCertificate(ip, domain, criticalDays, warningDays)
				
				mutex.Lock()
				results = append(results, result)
				mutex.Unlock()
			}(ip, domain)
		}
	}

	wg.Wait()
	return results
}

func checkCertificate(ip, domain string, criticalDays, warningDays int) Result {
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
		return Result{
			IP:       ip,
			Domain:   domain,
			Message:  fmt.Sprintf(" # %s - %s is bad: %v ", ip, domain, err),
			IsOK:     false,
			ExitCode: 2,
		}
	}
	defer conn.Close()

	// Get certificate details
	now := time.Now()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Result{
			IP:       ip,
			Domain:   domain,
			Message:  fmt.Sprintf(" # %s - %s has no certificates ", ip, domain),
			IsOK:     false,
			ExitCode: 2,
		}
	}

	cert := certs[0] // Use the first certificate
	validDays := int(cert.NotAfter.Sub(now).Hours() / 24)

	if validDays > warningDays {
		return Result{
			IP:       ip,
			Domain:   domain,
			Message:  fmt.Sprintf(" * %s - %s notAfter: %s. Exp.: %d day(s) ", ip, domain, cert.NotAfter.Format("Jan 02 15:04:05 2006 MST"), validDays),
			IsOK:     true,
			ExitCode: 0,
		}
	} else if validDays > criticalDays {
		return Result{
			IP:       ip,
			Domain:   domain,
			Message:  fmt.Sprintf(" # %s - %s The certificate is in warning state. Exp.: %d day(s) ", ip, domain, validDays),
			IsOK:     false,
			ExitCode: 1,
		}
	} else {
		return Result{
			IP:       ip,
			Domain:   domain,
			Message:  fmt.Sprintf(" # %s - %s The certificate is nearly expired. Exp.: %d day(s) ", ip, domain, validDays),
			IsOK:     false,
			ExitCode: 2,
		}
	}
}