# 🎣 PhishGuard — Hybrid Phishing URL Detector

<p align="left">
  <img src="https://img.shields.io/badge/python-3.6%2B-blue" alt="Python Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/status-active-success" alt="Status">
  <img src="https://img.shields.io/badge/detection-Rule--Based%20%2B%20ML-orange" alt="Hybrid Detection">
</p>

**PhishGuard** is a hybrid phishing URL detector — combining explainable, rule-based heuristics with a machine learning classifier to analyze any URL and produce a severity-rated risk score and verdict, without ever needing to actually visit the site in a browser.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Objectives](#-objectives)
- [Scope & Limitations](#-scope--limitations)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Architecture](#-architecture)
- [Technology Stack](#-technology-stack)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Module Details](#-module-details)
- [Scoring & Verdict System](#-scoring--verdict-system)
- [Reporting](#-reporting)
- [Sample Output](#-sample-output)
- [Testing & Performance](#-testing--performance)
- [Troubleshooting / FAQ](#-troubleshooting--faq)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Author](#-author)
- [Acknowledgments](#-acknowledgments)
- [Disclaimer](#-disclaimer)
- [License](#-license)

---

## 🧭 Overview

PhishGuard analyzes a URL across five independent dimensions — its structure, its domain registration history, known threat intelligence databases, its page content, and a trained machine learning model — then combines every signal into a single 0-100 risk score and a clear verdict (Legitimate / Suspicious / Phishing). It supports both single-URL analysis and bulk scanning of a URL list, producing severity-rated `.txt`, `.html`, and `.csv` reports.

## 🎯 Objectives

- Build a hybrid (rule-based + ML) phishing URL detection tool
- Analyze URLs across lexical structure, domain metadata, threat intelligence, page content, and ML classification
- Produce a single, explainable risk score with clear reasoning for every flag raised
- Support both single-URL and bulk (file-based) scanning
- Keep every check safe and non-destructive — no credentials are ever submitted, no scripts executed

## 🔒 Scope & Limitations

PhishGuard performs **detection and risk-scoring only** — it does not block, quarantine, or take any action against a URL. All content checks use a plain HTTP GET request; no JavaScript is executed and no forms are submitted. The ML classifier is trained on a **synthetic dataset** generated from documented phishing/legitimate URL feature distributions (see [Testing & Performance](#-testing--performance)) rather than a real-world labeled dataset — this keeps the project fully self-contained, but means its accuracy on the exact distributions it was trained on is not representative of production-grade accuracy on live traffic. Verdicts should always be treated as a decision aid, not a final authority — always verify manually before taking action on any flagged URL.

---

## 🧠 Features

### 🔤 Lexical Analysis (URL Structure)
| Check | What it looks for |
|---|---|
| URL Length | Unusually long URLs used to obscure the real destination |
| IP Address as Domain | Raw IP instead of a domain name |
| `@` Symbol | Used to disguise the real destination from browsers |
| Subdomain Count | Excessive nested subdomains mimicking a trusted brand |
| Hyphen Count | Multiple hyphens common in spoofed domains |
| HTTPS Usage | Missing TLS encryption |
| Suspicious Keywords | `login`, `verify`, `account`, `secure`, `update`, etc. |
| URL Shorteners | bit.ly, tinyurl, and similar destination-hiding services |
| Suspicious TLDs | `.tk`, `.ml`, `.ga`, `.xyz`, and other frequently-abused TLDs |
| Digit Density | High digit counts common in auto-generated phishing domains |

### 🕵️ Domain Intelligence
| Check | What it looks for |
|---|---|
| Domain Age (WHOIS) | Newly registered domains (under 30 days = strong indicator) |
| Typosquatting Detection | Edit-distance comparison against 18 frequently-impersonated brands |

### 🌐 Threat Intelligence
| Check | What it looks for |
|---|---|
| URLhaus Lookup | Cross-references the URL against abuse.ch's free, public known-malicious URL database |

### 📄 Content Analysis
| Check | What it looks for |
|---|---|
| Cross-Domain Password Forms | Login forms that submit credentials to a different domain than displayed |
| Brand Impersonation | Page text referencing a major brand while the domain doesn't match |

### 🤖 Machine Learning Classification
| Check | What it looks for |
|---|---|
| RandomForest Prediction | 12-feature lexical model producing a phishing probability score |

### 📊 Scoring & Reporting
- Every finding contributes weighted points to a single 0-100 risk score
- Clear verdict tiers: Likely Legitimate → Caution → Suspicious → Phishing (High Confidence)
- Single-URL reports in `.txt` and `.html`; bulk scans produce `.csv` and `.html` summaries

### ⚙️ Modularity & CLI Control
- Every check is an independent module, callable individually or as part of the full pipeline
- `cli.py` supports both `single` and `bulk` subcommands
- `main.py` provides an interactive entry point with a simple menu

---

## 📁 Project Structure

```
PhishGuard/
├── main.py                  # Interactive controller (single + bulk modes)
├── cli.py                   # Flag-based CLI
├── modules/
│   ├── lexical_analysis.py  # URL structure checks + ML feature extraction
│   ├── domain_check.py      # WHOIS age + typosquatting detection
│   ├── blacklist_check.py   # URLhaus threat intelligence lookup
│   ├── content_check.py     # Page content analysis
│   ├── ml_classifier.py     # Loads the trained model, returns a prediction
│   ├── train_model.py       # Generates synthetic data and trains the model
│   ├── scorer.py            # Aggregates findings into a score + verdict
│   └── report.py            # .txt / .html / .csv report generation
├── models/
│   └── phishguard_model.pkl # Pre-trained RandomForest model
├── reports/                 # Output folder for generated reports
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🏗️ Architecture

```
                    User (URL or file of URLs)
                             |
                             v
                    cli.py / main.py
                             |
        +---------+---------+---------+---------+
        |         |         |         |         |
   lexical    domain    blacklist  content      ml
   _analysis  _check    _check     _check    _classifier
        |         |         |         |         |
        +---------+---------+---------+---------+
                             |
                             v
                        scorer.py
                (aggregates points -> verdict)
                             |
                             v
                        report.py
              (.txt / .html single, .csv / .html bulk)
```

---

## 🛠️ Technology Stack

- **Language:** Python 3
- **Libraries:** `requests`, `beautifulsoup4`, `python-whois`, `scikit-learn`, `numpy`, `joblib`
- **ML Model:** RandomForestClassifier (scikit-learn), trained on 12 lexical URL features
- **Environment:** Cross-platform — tested on Windows

---

## ✅ Prerequisites

- Python **3.6+**
- `pip` package manager
- Internet access for WHOIS, threat intelligence, and content checks (lexical + ML checks work fully offline)

**`requirements.txt`**
```
requests>=2.31.0
beautifulsoup4>=4.12.0
python-whois>=0.9.4
scikit-learn>=1.3.0
numpy>=1.24.0
joblib>=1.3.0
```

---

## 🚀 Installation

```bash
git clone https://github.com/mahadzulfiqar/PhishGuard.git
cd PhishGuard
pip install -r requirements.txt
```

> Recommended: use a virtual environment to keep dependencies isolated.

```bash
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**On Windows**, if `pip` isn't recognized directly, use:
```powershell
python -m pip install -r requirements.txt
```

A pre-trained model is already included at `models/phishguard_model.pkl`, so no training step is required to get started. To retrain it (e.g. after modifying the feature set):
```bash
python modules/train_model.py
```

---

## 🚀 Usage

### Interactive mode (recommended for first-time use)

```bash
python3 main.py
```
Prompts for either a single URL or a path to a bulk URL list file.

### Single URL via CLI

```bash
python3 cli.py single -u https://example.com
```

### Bulk scan via CLI

Create a text file with one URL per line:
```
https://www.wikipedia.org
http://paypa1-secure-login-verify.tk/account/update?id=12345
https://faceb00k-login-secure.xyz/verify
```

Then run:
```bash
python3 cli.py bulk -f urls.txt
```

> **Note:** bulk mode expects a path to a *text file containing URLs*, not a URL itself — this is validated with a clear error message if you mix them up.

---

## 🔍 Module Details

### Lexical Analysis
Examines the URL string itself — no network request required. Checks length, IP-as-domain, `@` symbol abuse, subdomain/hyphen counts, HTTPS usage, suspicious keywords, shorteners, and TLD reputation. Also extracts a 12-dimension numeric feature vector shared with the ML classifier.

### Domain Check
Performs a WHOIS lookup to determine domain registration age (very new domains are a strong phishing signal) and compares the domain's word tokens against 18 frequently-impersonated brands using Levenshtein edit-distance, catching typosquatting patterns like `paypa1` vs `paypal`.

### Blacklist Check
Queries [URLhaus](https://urlhaus.abuse.ch/), a free public threat-intelligence feed, to check whether the URL has already been reported as malicious. Read-only — no submission, no API key required.

### Content Check
Fetches the page's raw HTML (plain GET request, no JavaScript execution) and checks for login/password forms that submit to a different domain than the one displayed, and for brand names mentioned in the page text that don't match the actual domain.

### ML Classification
Loads a pre-trained RandomForest model and predicts a phishing probability from the same 12 lexical features used in the rule-based analysis, contributing its own weighted score to the final verdict.

---

## 📊 Scoring & Verdict System

Every finding contributes weighted points (see each module for exact weights). Total points are capped at 100 and mapped to a verdict:

| Score Range | Verdict |
|---|---|
| 70-100 | **PHISHING** — High Confidence |
| 40-69 | **SUSPICIOUS** — Likely Phishing |
| 20-39 | **CAUTION** — Some Red Flags |
| 0-19 | **LIKELY LEGITIMATE** |

---

## 📄 Reporting

**Single URL scans** produce two files in `/reports/`:
- `.txt` — plain-text summary with full per-module detail
- `.html` — color-coded, browser-viewable report with a prominent verdict badge

**Bulk scans** produce:
- `.csv` — URL, score, and verdict for every scanned URL (easy to open in Excel)
- `.html` — a styled summary table of all results

---

## 🖥️ Sample Output

Real output from a verified run:

```
=== PhishGuard - Phishing URL Detector ===
Enter URL to analyze: http://paypa1-secure-login-verify.tk/account/update?id=12345

=== Analyzing: http://paypa1-secure-login-verify.tk/account/update?id=12345 ===

--- VERDICT ---
Risk Score: 100/100
Verdict:    PHISHING - High Confidence

--- TOP FLAGS ---
 - [Critical] Typosquatting Suspicion (+35 pts) - Domain 'paypa1-secure-login-verify.tk'
   differs from 'paypal.com' by only 1 character(s) - classic typosquatting pattern
 - [Critical] ML Classification (+30 pts) - RandomForest model prediction: 99% phishing probability
 - [Medium] Suspicious Keywords (+24 pts) - Keywords: login, verify, account, secure, update
 - [Medium] Suspicious TLD (+12 pts) - This TLD is frequently abused for disposable phishing domains
 - [Medium] Hyphens in Domain (+10 pts) - Multiple hyphens are common in spoofed domains

[+] Report saved to: reports/phishguard_paypa1-secure-login-verify.tk_..._....txt
[+] HTML report saved to: reports/phishguard_paypa1-secure-login-verify.tk_..._....html
```

And a clean legitimate URL, for comparison:
```
Enter URL to analyze: https://www.wikipedia.org

--- VERDICT ---
Risk Score: 0/100
Verdict:    LIKELY LEGITIMATE

--- TOP FLAGS ---
No significant red flags detected.
```

---

## 🧪 Testing & Performance

### Test Strategy
The rule-based modules were tested against both a constructed phishing-style URL (`paypa1-secure-login-verify.tk`, deliberately combining typosquatting, suspicious keywords, a disposable TLD, and no HTTPS) and a known-legitimate URL (`wikipedia.org`), confirming correct classification with zero false positives in both directions. Bulk mode was tested with a mixed list of legitimate and phishing-style URLs.

### About the ML Model's Training Data
The bundled model is trained on a **synthetically generated dataset** of 3,000 samples (1,500 legitimate-pattern, 1,500 phishing-pattern), constructed from documented statistical differences between real phishing and legitimate URLs (e.g. phishing URLs tend to be longer, use more suspicious keywords, and lack HTTPS more often). This was a deliberate choice to keep the project fully self-contained without requiring an external dataset download. Reported test accuracy on this synthetic holdout set is ~99%, which reflects how well the model learned the synthetic generating distributions — **not** real-world accuracy on live phishing traffic. For production use, `modules/train_model.py` should be adapted to load a real labeled dataset (e.g. PhishTank or the UCI Phishing Websites dataset) via `pandas.read_csv()` in place of `generate_synthetic_dataset()`.

### Test Cases
- Typosquatted domain (`paypa1...`) correctly flagged as Critical with 1-character edit distance to `paypal.com`
- Legitimate high-traffic domain (`wikipedia.org`) correctly scored 0/100 with no false positives
- Bulk mode correctly processes a mixed list and produces accurate per-URL verdicts
- Network-dependent modules (WHOIS, threat intel, content fetch) degrade gracefully with clear "Unavailable" messages rather than crashing when a target is unreachable
- Invalid bulk file paths produce a clear, actionable error message instead of a raw traceback

### Performance Metrics
| Module | Approx. Time |
|---|---|
| Lexical Analysis | < 0.1s (offline) |
| ML Classification | < 0.1s (offline) |
| Domain Check (WHOIS) | 1-3s (network-dependent) |
| Threat Intelligence Lookup | 1-2s (network-dependent) |
| Content Analysis | 1-3s (network-dependent) |
| Full Single-URL Scan | ~3-8s typical |

---

## 🛠️ Troubleshooting / FAQ

**Q: `pip` isn't recognized on Windows.**
A: Use `python -m pip install -r requirements.txt` instead of calling `pip` directly.

**Q: `InconsistentVersionWarning` when running a scan.**
A: This is a harmless warning meaning the bundled model was trained on a slightly different scikit-learn version than what's installed locally. It does not affect correctness — retrain locally with `python modules/train_model.py` to silence it if desired.

**Q: WHOIS / threat intelligence / content checks show "Unavailable" or "Lookup Failed".**
A: These modules require outbound network access (WHOIS uses port 43, not standard HTTP). If you're on a restricted network, firewall, or VPN, these checks will fail gracefully while the offline modules (lexical analysis, typosquatting, ML) still run normally.

**Q: Bulk mode crashes or says "Invalid argument".**
A: Bulk mode expects a path to a **text file** containing URLs, one per line — not a URL typed directly. Create a `.txt` file with your URLs first, then pass its filename.

**Q: The ML model seems overconfident (always near 0% or 100%).**
A: This is expected given the model is trained on cleanly-separated synthetic data (see [Testing & Performance](#-testing--performance)). Real-world URLs with mixed characteristics would produce more graduated probabilities with a dataset trained on real traffic.

---

## 🔮 Roadmap

- [ ] Retrain on a real labeled phishing dataset (e.g. PhishTank, UCI Phishing Websites)
- [ ] Screenshot-based visual similarity detection (compare rendered page to known brand pages)
- [ ] Favicon hash comparison against known brand favicons
- [ ] Browser automation (headless) for JavaScript-rendered phishing pages
- [ ] Google Safe Browsing API integration as a second threat intel source
- [ ] Bulk scan progress bar and multithreading for large URL lists
- [ ] REST API mode for integration with other tools

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes with clear messages
4. Open a pull request describing what you changed and why

For larger changes, please open an issue first to discuss what you'd like to add or modify.

---

## 👤 Author

Developed by **Mahad Zulfiqar**.

---

## 🙏 Acknowledgments

- [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/) — free public threat-intelligence database
- [scikit-learn](https://scikit-learn.org/) — machine learning library
- [python-whois](https://pypi.org/project/python-whois/) — WHOIS lookup library
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) — HTML parsing library
- [APWG](https://apwg.org/) / [PhishTank](https://phishtank.org/) — phishing research and methodology reference

---

## ⚠️ Disclaimer

PhishGuard is intended for **educational and informational purposes**. It provides a risk assessment to aid decision-making — it is not a guarantee of a URL's safety or maliciousness, and should never be the sole basis for a security decision. Always verify manually (checking the domain directly, contacting the organization through a known channel, etc.) before entering credentials or sensitive information on any site, regardless of PhishGuard's verdict. The authors accept no liability for actions taken based on this tool's output.

---

## 📜 License

This project is released under the [MIT License](LICENSE) — feel free to use, modify, and distribute with attribution.


---

### 🔗 Part of a 3-Tool Security Toolkit

This project is one piece of a broader offensive/defensive security pipeline:

- 🛰️ **[ReconX](https://github.com/mahadzulfiqar09/ReconX)** — Reconnaissance & information gathering
- 🛡️ **[WebGuard](https://github.com/mahadzulfiqar09/WebGuard)** — Web application vulnerability scanning
- 🎣 **[PhishGuard](https://github.com/mahadzulfiqar09/PhishGuard)** — Hybrid phishing URL detection

Built and maintained by **[Mahad Zulfiqar](https://github.com/mahadzulfiqar09)**.
