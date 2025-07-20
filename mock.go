package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix" // Добавлен правильный импорт
	"errors"
	"net"
	"time"
)

// MockDNSResolver is a mock implementation of DNSResolver
type MockDNSResolver struct {
	DomainIPMap map[string][]string // Domain name -> IP addresses
}

func (m *MockDNSResolver) LookupIP(domain string) ([]net.IP, error) {
	ips, ok := m.DomainIPMap[domain]
	if !ok {
		return nil, errors.New("domain not found in mock data")
	}

	var result []net.IP
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			result = append(result, ip)
		}
	}
	return result, nil
}

// MockCertificateChecker is a mock implementation of CertificateChecker
type MockCertificateChecker struct {
	IPCertMap map[string]*MockCertData // IP address -> certificate data
}

type MockCertData struct {
	Domain      string
	NotBefore   time.Time
	NotAfter    time.Time
	Error       error
	NoCerts     bool
}

func (m *MockCertificateChecker) CheckCertificate(ip, domain string) (*tls.ConnectionState, error) {
	certData, ok := m.IPCertMap[ip]
	if !ok {
		return nil, errors.New("IP not found in mock data")
	}

	if certData.Error != nil {
		return nil, certData.Error
	}

	if certData.NoCerts {
		return &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}, nil
	}

	// Create a mock certificate
	cert := &x509.Certificate{
		NotBefore: certData.NotBefore,
		NotAfter:  certData.NotAfter,
		Subject: pkix.Name{  // Исправлено: x509.pkix -> pkix
			CommonName: domain,
		},
	}

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	return state, nil
}

// Helper function to create mock data based on the provided output
func CreateMockData() (*MockDNSResolver, *MockCertificateChecker) {
	// Parse the current date from the output
	currentDate, _ := time.Parse("2006-01-02 15:04:05", "2025-07-20 07:44:20")
	
	// Create DNS mock data
	dnsMap := map[string][]string{
		"img.revjet.com": {
			"162.55.141.29", "168.119.141.33", "142.132.210.157", 
			"72.251.228.32", "74.217.31.237", "40.160.13.83", "40.160.13.82",
			"15.204.101.57", "72.251.234.20", "15.204.101.54", "107.6.93.86",
			"5.223.56.42", "15.235.215.92", "51.79.230.21", "5.223.56.156",
		},
		"portal.revjet.com": {
			"168.119.91.188", "162.55.129.47", "136.243.104.171",
			"74.201.205.11", "74.201.205.12", "107.6.90.89",
		},
		"sourcegraph.revjet.info": {"10.254.151.1"},
		"op.revjet.info": {
			"10.253.244.1", "10.253.179.1", "10.251.113.1", 
			"10.254.163.1", "10.254.118.1", "10.251.55.1", "10.253.136.1",
		},
		"nodestage1.revjet.com": {"135.148.34.58", "147.135.9.67"},
		"img.inny.revjet.info": {"162.55.141.29", "168.119.141.33"},
		"img.invh.revjet.info": {"142.132.210.157", "15.204.101.54"},
	}

	resolver := &MockDNSResolver{
		DomainIPMap: dnsMap,
	}

	// Create certificate checker mock data
	certMap := make(map[string]*MockCertData)
	
	// Set all certificates as valid (based on the output)
	for domain, ips := range dnsMap {
		var notAfter time.Time
		
		switch domain {
		case "sourcegraph.revjet.info":
			notAfter = currentDate.AddDate(0, 0, 299) // May 16 2026
		case "op.revjet.info":
			notAfter = currentDate.AddDate(0, 0, 271) // Apr 17 2026
		default:
			notAfter = currentDate.AddDate(0, 0, 289) // May 05 2026
		}
		
		for _, ip := range ips {
			certMap[ip] = &MockCertData{
				Domain:    domain,
				NotBefore: currentDate.AddDate(-1, 0, 0), // 1 year ago
				NotAfter:  notAfter,
				Error:     nil,
				NoCerts:   false,
			}
		}
	}

	certChecker := &MockCertificateChecker{
		IPCertMap: certMap,
	}

	return resolver, certChecker
}