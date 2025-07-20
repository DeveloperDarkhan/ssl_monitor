package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestFormatResults(t *testing.T) {
	// Чтение моков
	data, err := os.ReadFile("test/mock_results.json")
	if err != nil {
		t.Fatalf("Failed to read mock file: %v", err)
	}

	var mockResults []Result
	if err := json.Unmarshal(data, &mockResults); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	out, exit := FormatResults(mockResults, time.Date(2025, 7, 20, 12, 8, 26, 0, time.UTC))

	// Проверка, что вывод содержит нужные строки
	if exit != 0 {
		t.Errorf("Expected exit code 0, got %d", exit)
	}
	if !contains(out, "Good news:") {
		t.Errorf("Missing 'Good news:' in output")
	}
	if !contains(out, "img.revjet.com") {
		t.Errorf("Expected domain not found in output")
	}
}

func contains(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || contains(str[1:], substr) || contains(str[:len(str)-1], substr))
}
