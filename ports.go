func ScanPorts() []string {
    tcp, _ := ioutil.ReadFile("/proc/net/tcp")
    return parseNetStat("tcp", tcp)
}

func parseNetStat(proto string, data []byte) []string {
    var results []string
    lines := strings.Split(string(data), "\n")[1:]
    for _, line := range lines {
        if strings.TrimSpace(line) == "" {
            continue
        }
        parts := strings.Fields(line)
        localHex := parts[1]
        state := parts[3]
        ipPort := parseHexIPPort(localHex)
        if state == "0A" { // Listening
            results = append(results, fmt.Sprintf("🔌 Open %s Port: %s", proto, ipPort))
        }
    }
    return results
}
