## mkrootkitscan

A fast, CLI-based rootkit and anomaly scanner for Linux systems. Written in Go for speed and portability.

## 🚀 Features

Scans for suspicious processes, ports, and modules

Detects tampered /etc/ld.so.preload

Lists hidden dotfiles in root

Verifies critical binary hashes (ls, ps, top)

Outputs reports in text, json, or html formats

mkrootkitscan/
├── main.go
├── scanner/
│   ├── processes.go
│   ├── ports.go
│   ├── modules.go
│   ├── preload.go
│   ├── files.go
│   └── report.go
└── go.mod


## 🔧 Installation

1. Install Go (if not installed)

sudo apt update && sudo apt install golang -y

2. Clone the Repo

git clone https://github.com/mxkdevops/mkrootkitscan.git
cd mkrootkitscan

3. Build the Scanner

go build -o mkrootkitscan main.go

▶️ Usage

Run a scan and generate report:
```bash
sudo ./mkrootkitscan --format=html       # Save as scan_report.html
sudo ./mkrootkitscan --format=json       # Save as scan_report.json
sudo ./mkrootkitscan --format=text       # Console output
sudo ./mkrootkitscan --format=html --quiet  # No console output
```
📁 Output Files
```bash
scan_report.json — JSON report

scan_report.html — User-friendly HTML report

scan_report.txt  — (optional, if added)
```
📸 Screenshots

HTML Output Preview:



JSON Output:
```bash
{
  "Processes": ["⚠️ Suspicious Process 101: /usr/sbin/apache2"],
  "Ports": ["🔌 Open Port: 0.0.0.0:22"],
  "Modules": [],
  "Preload": "",
  "Hidden": ["🔒 Hidden File/Dir: /.dockerenv"],
  "Hashes": ["📁 /bin/ls MD5: 1a79a4d60de6718e8e5b326e338ae533"],
  "Timestamp": "2025-05-31T12:34:56Z"
}
```
📌 Roadmap (To-Do)



📜 License

MIT

🙋‍♂️ Author

[Your Name]  |  yourwebsite.com  |  GitHub: @yourusername


