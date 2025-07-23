package main

import (
	"context"
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

const (
	defaultTimeout = 5 * time.Second
	pushJobName    = "ssl_monitor"
)

var pushGatewayURL string

func init() {
	flag.StringVar(&pushGatewayURL, "pushgateway", "http://127.0.0.1:9091", "Prometheus Pushgateway URL")
}

func main() {
	startTime := time.Now()
	status := "success"

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "PANIC: %v\n", r)
			status = "failure"
			_ = pushToGateway(nil, pushGatewayURL, pushJobName, time.Since(startTime).Seconds(), status)
			os.Exit(1)
		}
	}()

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage: ssl_monitor '{\"domain.com\":[\"alias1.domain.com\"]}'")
		status = "failure"
		_ = pushToGateway(nil, pushGatewayURL, pushJobName, time.Since(startTime).Seconds(), status)
		os.Exit(2)
	}

	var domainAliases map[string][]string
	if err := json.Unmarshal([]byte(flag.Arg(0)), &domainAliases); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		status = "failure"
		_ = pushToGateway(nil, pushGatewayURL, pushJobName, time.Since(startTime).Seconds(), status)
		os.Exit(2)
	}

	results := checkAllDomains(domainAliases)

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "No valid certificates were found")
		status = "failure"
		_ = pushToGateway(nil, pushGatewayURL, pushJobName, time.Since(startTime).Seconds(), status)
		os.Exit(3)
	}

	for _, r := range results {
		fmt.Printf("domain: %s, alias: %s, ip: %s, value: %d\n",
			r.Domain, r.Alias, r.IP, r.DaysLeft)
	}

	duration := time.Since(startTime).Seconds()
	err := pushToGateway(results, pushGatewayURL, pushJobName, duration, status)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error pushing to Pushgateway: %v\n", err)
		status = "failure"
		_ = pushToGateway(nil, pushGatewayURL, pushJobName, duration, status)
		os.Exit(4)
	}
}

func checkAllDomains(domainAliases map[string][]string) []Result {
	var results []Result
	var mutex sync.Mutex
	var wg sync.WaitGroup

	for domain, aliases := range domainAliases {
		for _, alias := range aliases {
			ips, err := net.LookupIP(alias)
			if err != nil {
				continue
			}

			for _, ip := range ips {
				ipStr := ip.String()
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
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:443", ip))
	if err != nil {
		return -1
	}
	defer conn.Close()

	client := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         domain,
	})

	handshakeDone := make(chan error, 1)
	go func() {
		handshakeDone <- client.Handshake()
	}()

	select {
	case <-ctx.Done():
		return -1 // timeout
	case err := <-handshakeDone:
		if err != nil {
			return -1
		}
	}

	now := time.Now()
	certs := client.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return -1
	}
	cert := certs[0]
	validDays := int(cert.NotAfter.Sub(now).Hours() / 24)
	return validDays
}

func pushToGateway(results []Result, pushURL, job string, duration float64, status string) error {
	registry, err := initMetrics(results, duration, status)
	if err != nil {
		return fmt.Errorf("initMetrics error: %w", err)
	}

	return push.New(pushURL, job).
		Gatherer(registry).
		Push()
}

func initMetrics(results []Result, duration float64, status string) (*prometheus.Registry, error) {
	registry := prometheus.NewRegistry()

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

	lastRunGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssl_certificate_last_successful_run",
		Help: "Timestamp of the last successful SSL certificate check.",
	})
	lastRunGauge.Set(float64(time.Now().Unix()))
	if err := registry.Register(lastRunGauge); err != nil {
		return nil, fmt.Errorf("registering lastRunGauge: %w", err)
	}

	durationHistogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ssl_certificate_duration_seconds",
		Help:    "Duration of the SSL certificate check in seconds.",
		Buckets: []float64{0.1, 1, 2, 3, 4, 5, 6, 7, 8},
	})
	durationHistogram.Observe(duration)
	if err := registry.Register(durationHistogram); err != nil {
		return nil, fmt.Errorf("registering durationHistogram: %w", err)
	}

	runCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ssl_monitor_run_total",
			Help: "Total number of ssl_monitor runs, labeled by result (success/failure).",
		},
		[]string{"status"},
	)
	runCounter.WithLabelValues(status).Inc()
	if err := registry.Register(runCounter); err != nil {
		return nil, fmt.Errorf("registering runCounter: %w", err)
	}

	return registry, nil
}