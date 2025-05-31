package main
func ScanProcesses() []string {
    var results []string
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
