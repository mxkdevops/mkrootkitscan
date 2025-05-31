package main
func ScanLDPreload() string {
    content, err := ioutil.ReadFile("/etc/ld.so.preload")
    if err == nil && strings.TrimSpace(string(content)) != "" {
        return "⚠️ Non-empty /etc/ld.so.preload: " + string(content)
    }
    return ""
}
