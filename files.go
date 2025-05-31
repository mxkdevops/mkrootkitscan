func ScanHiddenFiles() []string {
    files, _ := ioutil.ReadDir("/")
    var results []string
    for _, f := range files {
        if strings.HasPrefix(f.Name(), ".") {
            results = append(results, "🔒 Hidden File/Dir: /"+f.Name())
        }
    }
    return results
}
