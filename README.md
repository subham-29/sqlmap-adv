# 🔐 SQLi Scanner

> Advanced SQL Injection Scanner using Python & SQLMap — with interactive DB/Table/Column selection, clean reports, and CLI automation.

![Python](https://img.shields.io/badge/Python-3.6+-blue?logo=python)
![License](https://img.shields.io/github/license/subham-29/sqlmap-adv)
![Made with ❤️](https://img.shields.io/badge/Made%20by-Subham%20Panigrahi-green)

---

## ⚡ Features

- 🔍 SQLMap-powered SQL injection scanner (quick & deep modes)
- 🧠 Interactive DB ➝ Table ➝ Column selection with smart prompts
- 📊 HTML/CSV reports + colored console output
- 🌐 Supports crawling, form scanning, proxies, multithreading
- 🧪 Exports credentials, email dumps, full tables, or selected columns
- 🧾 Saves logs, generates clean outputs

---

## 📦 Installation

### ✅ Linux / Kali / Ubuntu
```bash
sudo apt install python3 python3-pip
sudo apt install sqlmap  # or git clone https://github.com/sqlmapproject/sqlmap
pip install -r requirements.txt
```

### ✅ Windows
```bash
# Ensure Python is added to PATH
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

> Make sure `sqlmap.py` is available in PATH or in the same directory.

### ✅ macOS
```bash
brew install python3
brew install sqlmap
pip3 install -r requirements.txt
```

### Optional (pip install as tool)
```bash
git clone https://github.com/subham-29/sqlmap-adv.git
cd sqlmap-adv
python3 setup.py install
python3 sqli_scanner.py -h
```
---

## 🚀 Usage

```bash
python3 sqli_scanner.py --url "http://testphp.vulnweb.com/listproducts.php?cat=1"
```

### 🔧 Arguments:
| Flag | Description |
|------|-------------|
| `--url` | Target URL to scan |
| `--quick` | Run fast payload-based test |
| `--deep` | Full SQLMap scan with dump |
| `--interactive` | Activate menu for selecting DB ➝ Table ➝ Column |
| `--crawl=N` | Crawl up to N links |       
| `--threads=N` | Set thread count (default: 5) |
| `--proxy http://127.0.0.1:8080` | Use proxy (e.g., with Burp Suite) |
| `--timeout=10` | Set custom request timeout |
| `--output output_folder` | Folder to save logs and dumps |

### Example:
```bash
python sqli_scanner.py --url "http://target.com/?id=1" --interactive --deep --proxy http://127.0.0.1:8080
```

---

## 📁 Outputs

- `vulnerable_<timestamp>.txt`
- `output_clean.txt`, `output.csv`
- `report_<target>.html`
- `target.json` *(raw dump)*

---

## 👨‍💻 Author

Made with 💚 by **Subham Panigrahi**  
🔗 [GitHub](https://github.com/subham-29) — [LinkedIn](https://www.linkedin.com/in/subham-panigrahi-495804322/)  
📬 Contributions and PRs welcome!

---

## 📜 License

**MIT License** — free to use, modify, and distribute. See `LICENSE` file for details.

> This tool is intended for **ethical and educational purposes only.** Do not use on sites without permission.

---

## ⭐ Star the Repo if You Like It!

Want new features like webhook alerts, plugin support, or Nuclei integration? Open an issue or drop a PR!
