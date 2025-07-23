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
const pushJobName = "ssl_monitor"

var pushGatewayURL string

func init() {
	flag.StringVar(&pushGatewayURL, "pushgateway", "http://127.0.0.1:9091", "Prometheus Pushgateway URL")
}

func main() {
	startTime := time.Now()
	flag.Parse()

	// Check if domain argument is provided
	if flag.NArg() < 1 {
		fmt.Println("Usage: ssl_monitor '{\"domain.com\":[\"alias1.domain.com\",\"alias2.domain.com\"]}'")
		os.Exit(2)
	}

	// Parse domains JSON
	var domainAliases map[string][]string
	if err := json.Unmarshal([]byte(flag.Arg(0)), &domainAliases); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(2)
	}

	results := checkAllDomains(domainAliases)

	// Print results in the required format
	for _, r := range results {
		fmt.Printf("domain: %s, alias: %s, ip: %s, value: %d\n",
			r.Domain, r.Alias, r.IP, r.DaysLeft)
	}

	// Send metrics to Prometheus Pushgateway
	duration := time.Since(startTime).Seconds()
	err := pushToGateway(results, pushGatewayURL, pushJobName, duration)
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


func pushToGateway(results []Result, pushURL, job string, duration float64) error {
	registry, err := initMetrics(results, duration)
	if err != nil {
		return fmt.Errorf("initMetrics error: %w", err)
	}

	return push.New(pushURL, job).
		Gatherer(registry).
		Push()
}

func initMetrics(results []Result, duration float64) (*prometheus.Registry, error) {
	registry := prometheus.NewRegistry()

	// Используем GaugeVec для ssl_certificate_days_left
	daysLeftVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssl_certificate_days_left",
			Help: "Number of days left until SSL certificate expires.",
		},
		[]string{"domain", "alias", "ip"},
	)

	for _, r := range results {
		daysLeftVec.WithLabelValues(r.Domain, r.Alias, r.IP).Set(float64(r.DaysLeft))
	}
	if err := registry.Register(daysLeftVec); err != nil {
		return nil, fmt.Errorf("registering daysLeftVec: %w", err)
	}

	// Метрика времени последнего успешного запуска
	lastRunGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssl_certificate_last_successful_run",
		Help: "Timestamp of the last successful SSL certificate check.",
	})
	lastRunGauge.Set(float64(time.Now().Unix()))
	if err := registry.Register(lastRunGauge); err != nil {
		return nil, fmt.Errorf("registering lastRunGauge: %w", err)
	}

	// Histogram с явными bucket-ами
	durationHistogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ssl_certificate_duration_seconds",
		Help:    "Duration of the SSL certificate check in seconds.",
		Buckets: []float64{0.1, 1, 2, 3, 4, 5, 6, 7, 8}, // custom buckets: 0.1s, 1s, 2s, ..., 8s
	})
	durationHistogram.Observe(duration)
	if err := registry.Register(durationHistogram); err != nil {
		return nil, fmt.Errorf("registering durationHistogram: %w", err)
	}

	return registry, nil
}
