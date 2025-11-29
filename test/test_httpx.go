package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"moongazing/scanner"
)

func main() {
	httpx := scanner.NewHttpxScanner(10)

	targets := []string{
		"baidu.com",
		"www.baidu.com",
		"aliyun.com",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results := httpx.EnrichSubdomains(ctx, targets)

	for _, r := range results {
		fmt.Printf("\n=== %s ===\n", r.Host)
		fmt.Printf("URL: %s\n", r.URL)
		fmt.Printf("IP: %s\n", r.IP)
		fmt.Printf("IPs: %v\n", r.IPs)
		fmt.Printf("StatusCode: %d\n", r.StatusCode)
		fmt.Printf("Title: %s\n", r.Title)
		fmt.Printf("WebServer: %s\n", r.WebServer)
		fmt.Printf("CDN: %v (%s)\n", r.CDN, r.CDNName)
		fmt.Printf("Technologies: %v\n", r.Technologies)
		fmt.Printf("ResponseTime: %v\n", r.ResponseTime)

		// JSON 输出
		jsonData, _ := json.MarshalIndent(r, "", "  ")
		fmt.Printf("\nJSON:\n%s\n", string(jsonData))
	}
}
