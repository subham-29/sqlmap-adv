
# 🔐 SQLi Scanner

> A beginner-friendly yet powerful SQL Injection Scanner made using Python & SQLMap — built by an 18-year-old with a passion for cybersecurity.

![Python](https://img.shields.io/badge/Python-3.6+-blue?logo=python)
![License](https://img.shields.io/github/license/subham-29/sqlmap-adv)
![Built by a Beginner](https://img.shields.io/badge/Built%20by-18%20Y.O.%20Beginner-green)

---

## ⚡ What It Does

This is a tool I built to help test websites for **SQL Injection vulnerabilities** using SQLMap in the backend. It supports:

- 🔍 Quick + Deep scan modes using SQLMap
- 🧠 Interactive exploration of databases (choose DB ➝ Table ➝ Column)
- 📊 Clean HTML/CSV reports + colorful terminal output
- 🌐 Features like crawling, form scanning, proxy use, and multithreading
- 🧪 Dumps credentials or selected data from vulnerable sites
- 🧾 Saves logs and generates clean, readable output

---

## 📦 How to Install

> Works on **Linux**, **Windows**, and **macOS**!

### 🐧 Linux / Kali / Ubuntu
```bash
sudo apt install python3 python3-pip
sudo apt install sqlmap  # or git clone https://github.com/sqlmapproject/sqlmap
pip install -r requirements.txt
```

### 🪟 Windows
```bash
# Make sure Python is installed and added to PATH
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

### 🍎 macOS
```bash
brew install python3
brew install sqlmap
pip3 install -r requirements.txt
```

---

### Optional: Install as a Tool
```bash
git clone https://github.com/subham-29/sqlmap-adv.git
cd sqlmap-adv
sudo python3 setup.py install
python3 sqli_scanner.py -h
```

---

## 🚀 How to Use

### Basic Scan
```bash
python sqli_scanner.py --url "https://example.com/page.php?id=1"
```

### With More Options
```bash
python sqli_scanner.py --url "https://example.com/page.php?id=1" \
                      --threads 8 \
                      --crawl-depth 5 \
                      --timeout 15 \
                      --verbosity 2 \
                      --output-dir "scan_results" \
                      --proxy "http://127.0.0.1:8080" \
                      --interactive
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--url` | Target website URL |
| `--threads` | How many scans at once (default: 5) |
| `--crawl-depth` | How deep to crawl (default: 3) |
| `--timeout` | Timeout for requests (default: 10s) |
| `--verbosity` | Level of detail (0-3) |
| `--output-dir` | Folder to save scan results |
| `--proxy` | Use a proxy (like Burp Suite) |
| `--interactive` | Browse database interactively |
| `--quick-creds` | Try to quickly dump credentials |

---

## 🔄 How It Works

1. **Discovery**: Finds URLs with possible injection points
2. **Quick Scan**: Tries basic SQLi payloads
3. **Deep Scan**: Uses SQLMap to test more thoroughly
4. **Explore**: Lets you browse and extract from the database
5. **Report**: Generates neat HTML + CSV reports

---

## 🧠 Interactive DB Explorer

If a site is vulnerable, you can:

- Explore databases, tables, columns
- Extract emails, credentials, or anything else
- Save what you find in a file (CSV format)

---

## 📝 Sample Report

Each scan gives you:

- ✅ Vulnerability summary
- 🧨 List of affected URLs + risk levels
- 🔐 Sensitive data (if found)
- 🛡️ Fix suggestions
- 🧾 Technical logs (for learning)

---

## ⚠️ Legal Stuff

> This tool is for **learning and ethical testing** only.

Don’t scan any website unless **you own it** or have **permission** to test it. Hacking into websites without permission is **illegal** and can get you in serious trouble.

---

## 👦 About Me

Hi! I’m **Subham Panigrahi**, an 18-year-old just getting started with Python, ethical hacking, and cybersecurity. I built this project to learn how tools like SQLMap work and to share something helpful with other beginners.

- 💼 [LinkedIn](https://www.linkedin.com/in/subham-panigrahi-495804322/)
- 🛠️ Always learning | Beginner CTF player | Python + SQL enthusiast

---

## 📜 License

This project is open-source under the MIT License — check the [LICENSE](LICENSE) file.

---

## 🙏 Thanks To

- The amazing **SQLMap** devs for making such a great tool
- Python open-source community
- Everyone sharing knowledge online that helped me learn!
