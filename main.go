package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
)

type Result struct {
	Domain   string
	Alias    string
	IP       string
	DaysLeft int
}

const defaultTimeout = 5 * time.Second
const pushGatewayURL = "http://prometheus-pushgateway.in.revjet.info" // Измени на свой pushgateway URL
const pushJobName = "ssl_monitor"

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

	// Отправка метрик в Prometheus Pushgateway
	err := pushToGateway(results, pushGatewayURL, pushJobName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error pushing to Pushgateway: %v\n", err)
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
		Timeout: defaultTimeout,
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

func getLocation() string {
	host := os.Getenv("HOSTNAME")
	if host == "" {
		return "undefined"
	}
	return host
}

func pushToGateway(results []Result, pushURL, job string) error {
    location := getLocation()
    
    // Создаем новый реестр для всех метрик
    registry := prometheus.NewRegistry()
    
    // Для каждого результата создаем отдельную метрику
    for _, r := range results {
        gauge := prometheus.NewGauge(prometheus.GaugeOpts{
            Name: "ssl_certificate_days_left",
            Help: "Number of days left until SSL certificate expires.",
            ConstLabels: prometheus.Labels{
                "domain":   r.Domain,
                "alias":    r.Alias,
                "ip":       r.IP,
                "location": location,
            },
        })
        
        // Устанавливаем значение и регистрируем метрику
        gauge.Set(float64(r.DaysLeft))
        registry.MustRegister(gauge)
    }
    
    // Отправляем все метрики за один раз
    return push.New(pushURL, job).
        Gatherer(registry).
        Push()
}