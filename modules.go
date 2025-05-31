func ScanModules() []string {
    data, _ := ioutil.ReadFile("/proc/modules")
    lines := strings.Split(string(data), "\n")
    var results []string
    for _, line := range lines {
        if strings.Contains(line, "rootkit") {
            results = append(results, "⚠️ Suspicious Kernel Module: "+line)
        }
    }
    return results
}
