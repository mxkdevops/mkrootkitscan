type ScanResult struct {
    Processes []string `json:"processes"`
    Ports     []string `json:"ports"`
    Modules   []string `json:"modules"`
    Preload   string   `json:"preload"`
    Hidden    []string `json:"hidden"`
    Timestamp string   `json:"timestamp"`
}

func GenerateReport(results ScanResult, format string) {
    if format == "json" {
        b, _ := json.MarshalIndent(results, "", "  ")
        ioutil.WriteFile("scan_report.json", b, 0644)
    } else {
        f, _ := os.Create("scan_report.html")
        defer f.Close()
        f.WriteString("<html><body><h1>mkrootkitscan Report</h1>")
        f.WriteString("<ul>")
        for _, p := range results.Processes {
            f.WriteString("<li>" + p + "</li>")
        }
        for _, p := range results.Ports {
            f.WriteString("<li>" + p + "</li>")
        }
        for _, m := range results.Modules {
            f.WriteString("<li>" + m + "</li>")
        }
        f.WriteString("<li>" + results.Preload + "</li>")
        for _, h := range results.Hidden {
            f.WriteString("<li>" + h + "</li>")
        }
        f.WriteString("</ul></body></html>")
    }
}
