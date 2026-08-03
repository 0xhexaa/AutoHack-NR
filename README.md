# AutoHack NR

Automated Vulnerability Discovery — For the Good Guys.

Python 3.8+ | MIT License | Experimental

EDUCATIONAL PURPOSES ONLY
This tool is designed for security research, authorized testing, and learning.
Unauthorized use against systems you do not own or have explicit permission to test is illegal.
You are responsible for your actions.

---

What is AutoHack NR?

AutoHack NR is a Python-based security research tool that automates the discovery of vulnerabilities in web applications, devices, and network services.

It was born out of a simple observation: in late 2025, Anthropic and OpenAI publicly disclosed that their AI models had autonomously hacked multiple companies during internal red-team exercises. That got us thinking — if AI can break things at scale, why can't we build tools to find those breaks first, and fix them?

This is our answer.

NR stands for New Reality.
Because AI is no longer a distant future — it's here, it's capable, and it's going to take over.
In this new reality, defenders need automated weapons too.

---

Contributors

Hexa
GitHub: @0xhexaa
Role: Lead Developer

Axiom
GitHub: @imstillaxiom
Role: Co-Developer / Security Research

---

Current Features

SQL Injection Automation
- Fully automatic SQLi detection and exploitation
- Supports:
  - Error-based
  - Union-based
  - Boolean blind
  - Time-based blind
  - Stacked queries (where supported)
- Multi-threaded scanning
- Smart parameter filtering
- Proxy support (HTTP/SOCKS)
- Customizable payload lists

Planned Modules (Roadmap)
- XSS (Reflected & Stored)
- Command Injection
- Path Traversal
- Open Redirect
- CVE-based service fingerprinting
- AI-assisted fuzzing (GPT-powered payload generation)
- Automatic report generation (PDF/HTML)

---

Installation

git clone https://github.com/0xhexaa/autohack-nr.git
cd autohack-nr
pip install -r requirements.txt
python autohack.py --help

Requirements
- Python 3.8+
- requests, beautifulsoup4, urllib3, colorama

---

Usage

Basic SQL Injection Scan

python autohack.py -u "http://target.com/page?id=1" --sql

Advanced Options

python autohack.py -u "http://target.com/search?q=test" \
    --sql \
    --level 5 \
    --threads 20 \
    --proxy "http://127.0.0.1:8080" \
    --output report.json

Flags

-u, --url       Target URL (with parameters)
--sql           Enable SQL injection module
--level         Depth of testing (1-5, default: 3)
--threads       Number of concurrent threads
--proxy         Proxy URL (e.g., http://127.0.0.1:8080)
--timeout       Request timeout in seconds
-o, --output    Save results to JSON file
--verbose       Enable debug output

---

Philosophy

"The best defense is a good offense — but only if you're the one swinging first."

AutoHack NR isn't about causing damage. It's about finding damage before the bad guys do, and doing it faster than any human could. In a world where AI can launch thousands of attacks per second, we need automated tools that can scan, detect, and patch at the same speed.

We believe in:
- Transparency — all code is open source
- Responsibility — use it only on systems you own or have permission to test
- Continuous improvement — security is a moving target

---

Legal & Ethical Disclaimer

By using AutoHack NR, you agree to:

1. Use this tool only on systems you own or have explicit written permission to test.
2. Not use it for any malicious, unauthorized, or illegal activity.
3. Accept full responsibility for your actions.

The authors (Hexa and Axiom) are not liable for any misuse or damage caused by this tool.
It is provided "as-is" for educational and research purposes.

---

Contributing

We welcome contributions. Whether it's:
- New vulnerability modules
- Better payloads
- Performance improvements
- Documentation fixes

Please open an issue or submit a pull request.

---

License

This project is licensed under the MIT License — see the LICENSE file for details.

---

Connect

Hexa
GitHub: https://github.com/0xhexaa
Twitter: https://twitter.com/0xhexaa

Axiom
GitHub: https://github.com/imstillaxiom
Twitter: https://twitter.com/imstillaxiom

---

Star this repo if you believe in ethical security automation.
Stay safe. Stay legal. Stay ahead.

Made with coffee and a healthy dose of paranoia.