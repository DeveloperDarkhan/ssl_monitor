package main

import (
	"encoding/json"
	"fmt"
	"time"
)

func main() {
	// Parse the test date
	testDate, _ := time.Parse("2006-01-02 15:04:05", "2025-07-20 08:25:08")
	
	// Create mock implementations
	mockResolver, mockChecker := CreateMockData()
	
	// Define test scenarios with different domain lists
	testScenarios := []struct {
		name         string
		domainList   string
		criticalDays int
		warningDays  int
	}{
		{
			name:         "All certificates valid",
			domainList:   `{"img.revjet.com": ["img.inny.revjet.info", "img.invh.revjet.info"], "portal.revjet.com": ["portal.revjet.com"]}`,
			criticalDays: 14,
			warningDays:  30,
		},
		{
			name:         "Single domain test",
			domainList:   `{"sourcegraph.revjet.info": ["sourcegraph.revjet.info"]}`,
			criticalDays: 14,
			warningDays:  30,
		},
	}
	
	// Run each test scenario
	for _, scenario := range testScenarios {
		fmt.Printf("===== Running scenario: %s =====\n", scenario.name)
		
		var domainAliases map[string][]string
		if err := json.Unmarshal([]byte(scenario.domainList), &domainAliases); err != nil {
			fmt.Printf("Error parsing JSON: %v\n", err)
			continue
		}
		
		results := checkAllDomains(
			domainAliases, 
			scenario.criticalDays, 
			scenario.warningDays, 
			mockResolver, 
			mockChecker, 
			testDate,
		)
		
		ok, bad, exitCode := formatResults(results)
		fmt.Printf("%s %s %s\n", testDate.Format("2006-01-02 15:04:05"), ok, bad)
		fmt.Printf("Exit code: %d\n\n", exitCode)
	}
	
	// Add test scenario for certificate near warning threshold
	addWarningCertificate(mockChecker, "162.55.141.29", testDate.AddDate(0, 0, 25))
	fmt.Println("===== Running scenario: Certificate in warning state =====")
	domainAliases := map[string][]string{
		"img.revjet.com": {"img.inny.revjet.info"},
	}
	results := checkAllDomains(domainAliases, 14, 30, mockResolver, mockChecker, testDate)
	ok, bad, exitCode := formatResults(results)
	fmt.Printf("%s %s %s\n", testDate.Format("2006-01-02 15:04:05"), ok, bad)
	fmt.Printf("Exit code: %d\n\n", exitCode)
	
	// Add test scenario for certificate near critical threshold
	addWarningCertificate(mockChecker, "168.119.141.33", testDate.AddDate(0, 0, 10))
	fmt.Println("===== Running scenario: Certificate in critical state =====")
	results = checkAllDomains(domainAliases, 14, 30, mockResolver, mockChecker, testDate)
	ok, bad, exitCode := formatResults(results)
	fmt.Printf("%s %s %s\n", testDate.Format("2006-01-02 15:04:05"), ok, bad)
	fmt.Printf("Exit code: %d\n\n", exitCode)
}

// Helper function to modify a certificate in the mock data
func addWarningCertificate(checker *MockCertificateChecker, ip string, expiry time.Time) {
	certData := checker.IPCertMap[ip]
	if certData != nil {
		certData.NotAfter = expiry
	}
}