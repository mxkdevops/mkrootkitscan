package main

import (
    "fmt"
    "time"
)

// You must declare the ScanResult type and the functions used here,
// or import them if they are in separate files (e.g., processes.go, ports.go, etc.)

func main() {
    results := ScanResult{
        Processes: ScanProcesses(),
        Ports:     ScanPorts(),
        Modules:   ScanModules(),
        Preload:   ScanLDPreload(),
        Hidden:    ScanHiddenFiles(),
        Timestamp: time.Now().Format(time.RFC3339),
    }

    fmt.Println("✅ Scan complete. Saving report...")
    GenerateReport(results, "html")
    fmt.Println("📄 Report saved to scan_report.html")
}
