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
