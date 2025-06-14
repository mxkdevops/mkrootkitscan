// mkrootkitscan - CLI Rootkit Scanner
// GitHub-ready version with CLI flags and report generation
package main

import (
    "crypto/md5"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "net"
    "os"
    "strconv"
    "strings"
    "time"
)

type ScanResult struct {
    Processes []string `json:"processes"`
    Ports     []string `json:"ports"`
    Modules   []string `json:"modules"`
    Preload   string   `json:"preload"`
    Hidden    []string `json:"hidden"`
    Hashes    []string `json:"hashes"`
    Timestamp string   `json:"timestamp"`
}

func ScanProcesses() []string {
    results := make([]string, 0) // initialize empty slice
    entries, _ := ioutil.ReadDir("/proc")
    for _, entry := range entries {
        if pid, err := strconv.Atoi(entry.Name()); err == nil {
            cmd, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
            if err == nil && strings.Contains(string(cmd), "ld.so.preload") {
                results = append(results, fmt.Sprintf("⚠️ Suspicious Process %d: %s", pid, string(cmd)))
            }
        }
    }
    return results
}

func parseHexIPPort(hexStr string) string {
    parts := strings.Split(hexStr, ":")
    ip := parts[0]
    port := parts[1]
    ipBytes := make([]byte, 4)
    for i := 0; i < 4; i++ {
        b, _ := strconv.ParseUint(ip[2*i:2*i+2], 16, 8)
        ipBytes[i] = byte(b)
    }
    ipStr := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]).String()
    p, _ := strconv.ParseInt(port, 16, 32)
    return fmt.Sprintf("%s:%d", ipStr, p)
}

func ScanPorts() []string {
    results := make([]string, 0) // initialize empty slice
    tcp, _ := ioutil.ReadFile("/proc/net/tcp")
    lines := strings.Split(string(tcp), "\n")[1:]
    for _, line := range lines {
        if strings.TrimSpace(line) == "" {
            continue
        }
        parts := strings.Fields(line)
        localHex := parts[1]
        state := parts[3]
        if state == "0A" {
            results = append(results, "🔌 Open Port: "+parseHexIPPort(localHex))
        }
    }
    return results
}

func ScanModules() []string {
    results := make([]string, 0) // initialize empty slice
    data, _ := ioutil.ReadFile("/proc/modules")
    lines := strings.Split(string(data), "\n")
    for _, line := range lines {
        if strings.Contains(line, "rootkit") {
            results = append(results, "⚠️ Suspicious Module: "+line)
        }
    }
    return results
}

func ScanLDPreload() string {
    content, err := ioutil.ReadFile("/etc/ld.so.preload")
    if err == nil && strings.TrimSpace(string(content)) != "" {
        return "⚠️ Non-empty /etc/ld.so.preload: " + string(content)
    }
    return ""
}

func ScanHiddenFiles() []string {
    results := make([]string, 0) // initialize empty slice
    files, _ := ioutil.ReadDir("/")
    for _, f := range files {
        if strings.HasPrefix(f.Name(), ".") {
            results = append(results, "🔒 Hidden File/Dir: /"+f.Name())
        }
    }
    return results
}

func ScanCriticalFileHashes() []string {
    results := make([]string, 0) // initialize empty slice
    paths := []string{"/bin/ls", "/bin/ps", "/usr/bin/top"}
    for _, path := range paths {
        content, err := ioutil.ReadFile(path)
        if err == nil {
            hash := fmt.Sprintf("%x", md5sum(content))
            results = append(results, fmt.Sprintf("📁 %s MD5: %s", path, hash))
        }
    }
    return results
}

func md5sum(data []byte) []byte {
    h := md5.New()
    h.Write(data)
    return h.Sum(nil)
}

func GenerateReport(results ScanResult, format string) {
	switch format {
	case "json":
		b, _ := json.MarshalIndent(results, "", "  ")
		ioutil.WriteFile("scan_report.json", b, 0644)
	case "html":
		f, _ := os.Create("scan_report.html")
		defer f.Close()

		style := `
		<style>
		body { font-family: Arial, sans-serif; background-color: #f8f9fa; padding: 20px; }
		h1 { color: #343a40; }
		ul { list-style-type: none; padding: 0; }
		li { margin: 8px 0; padding: 10px; border-radius: 6px; }
		li.warning { background-color: #ffeeba; border-left: 5px solid #ffc107; }
		li.info { background-color: #e2e3e5; border-left: 5px solid #6c757d; }
		li.good { background-color: #d4edda; border-left: 5px solid #28a745; }
		footer { margin-top: 30px; font-style: italic; color: #666; }
		</style>
		`

		f.WriteString("<html><head><title>mkrootkitscan Report</title>" + style + "</head><body>")
		f.WriteString("<h1>mkrootkitscan Report</h1><ul>")

		writeSection := func(title string, items []string) {
			if len(items) == 0 {
				return
			}
			f.WriteString(fmt.Sprintf("<h2>%s</h2>", title))
			for _, item := range items {
				class := "info"
				if strings.Contains(item, "⚠️") {
					class = "warning"
				} else if strings.Contains(item, "🔌") || strings.Contains(item, "📁") {
					class = "good"
				}
				f.WriteString(fmt.Sprintf("<li class='%s'>%s</li>", class, item))
			}
		}

		writeSection("Suspicious Processes", results.Processes)
		writeSection("Open Ports", results.Ports)
		writeSection("Kernel Modules", results.Modules)
		if results.Preload != "" {
			f.WriteString(fmt.Sprintf("<li class='warning'>%s</li>", results.Preload))
		}
		writeSection("Hidden Files", results.Hidden)
		writeSection("Binary Hashes", results.Hashes)

		f.WriteString(fmt.Sprintf("<footer><p>Scan Time: %s</p></footer>", results.Timestamp))
		f.WriteString("</body></html>")
	default:
		fmt.Println("[Text Output]")
		for _, l := range results.Processes {
			fmt.Println(l)
		}
		for _, l := range results.Ports {
			fmt.Println(l)
		}
		for _, l := range results.Modules {
			fmt.Println(l)
		}
		if results.Preload != "" {
			fmt.Println(results.Preload)
		}
		for _, l := range results.Hidden {
			fmt.Println(l)
		}
		for _, l := range results.Hashes {
			fmt.Println(l)
		}
	}
}


func main() {
    outputFormat := flag.String("format", "text", "Output format: text, html, or json")
    quiet := flag.Bool("quiet", false, "Suppress console output")
    flag.Parse()

    results := ScanResult{
        Processes: ScanProcesses(),
        Ports:     ScanPorts(),
        Modules:   ScanModules(),
        Preload:   ScanLDPreload(),
        Hidden:    ScanHiddenFiles(),
        Hashes:    ScanCriticalFileHashes(),
        Timestamp: time.Now().Format(time.RFC3339),
    }

    if !*quiet {
        fmt.Println("✅ Scan complete. Generating report...")
    }
    GenerateReport(results, *outputFormat)
    if !*quiet {
        fmt.Println("📄 Report saved")
    }
}
