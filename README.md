# GitlabHarvester — Global GitLab Code & Secret Search Tool (Python)

![PyPI](https://img.shields.io/pypi/v/gitlab-harvester)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/github/license/Cur1iosity/GitlabHarvester)
![Last Commit](https://img.shields.io/github/last-commit/Cur1iosity/GitlabHarvester)

**GitlabHarvester** is a fast, scalable tool for searching keywords across an entire GitLab instance using the API — without cloning repositories.
Built for **security audits, secret discovery, compliance checks, and large-scale code intelligence** across thousands of projects.

> Global term search across a full GitLab instance — especially valuable for GitLab CE environments.

---

## ⚡ Quick Start

Search a keyword:

```bash
gitlab-harvester -u https://gitlab.example.com -t $TOKEN --search password
```

Search from file:

```bash
gitlab-harvester -u https://gitlab.example.com -t $TOKEN --terms-file words.txt
```

Build project index only:

```bash
gitlab-harvester -u https://gitlab.example.com -t $TOKEN -m dump-index
```

Deduplicate results:

```bash
gitlab-harvester -m dedup --input-file session.jsonl --output-file clean.jsonl
```

Convert JSONL → JSON:

```bash
gitlab-harvester -m convert --input-file session.jsonl --output-file result.json
```

---

## 🚀 Overview

GitLab Community Edition does not provide full instance-wide code search like EE.
GitlabHarvester fills this gap by:

* building a lightweight instance project index
* scanning repositories via API
* streaming results in JSONL
* supporting resumable sessions
* keeping memory usage constant

Designed to operate efficiently on environments with **10k–100k repositories**.

---

## 🔍 Key Advantages

| Problem                 | Solution               |
| ----------------------- | ---------------------- |
| No global search        | Instance-wide scan     |
| Cloning thousands repos | API-only scanning      |
| Large instances         | Streaming architecture |
| Repeated audits         | Cached project index   |

---

## ✨ Features

* Instance-wide keyword search
* No repository cloning
* JSONL project index
* Branch scanning strategies
* Smart fork analysis
* Resume interrupted scans
* Streaming output
* Low memory footprint
* Automation-friendly
* Built-in post-processing tools

---

## 📦 Installation

### Recommended — install from PyPI

```bash
pipx install gitlab-harvester
```

Run:

```bash
gitlab-harvester --help
```

---

### Alternative — pip

```bash
pip install gitlab-harvester
```

---

### Development install

```bash
git clone https://github.com/Cur1iosity/GitlabHarvester.git
cd GitlabHarvester
pip install .
```

Editable mode:

```bash
pip install -e .
```

---

### Install latest dev version

```bash
pipx install git+https://github.com/Cur1iosity/GitlabHarvester.git
```

---

## Requirements

* Python **3.10+**
* GitLab token with **read_api** permission

---

## 🌿 Branch Control

Two independent controls:

* `--index-branches` — stored branches
* `--scan-branches` — scanned branches

Example:

```bash
gitlab-harvester -u ... -t ... --scan-branches 10
```

Store all + scan all:

```bash
gitlab-harvester -u ... -t ... --index-branches all --scan-branches all
```

Shortcut:

```bash
--branches N
```

---

## 🍴 Fork Strategies

```
--forks skip|include|branch-diff|all-branches
```

Recommended → **branch-diff**

| Mode         | Behavior                       |
| ------------ | ------------------------------ |
| skip         | ignore forks                   |
| include      | treat as normal repos          |
| branch-diff  | scan default + unique branches |
| all-branches | full exhaustive scan           |

---

## 💾 Sessions & Resume

Create session:

```bash
gitlab-harvester -u ... -t ... --terms-file words.txt --session audit
```

Resume:

```bash
gitlab-harvester -u ... -t ... --session-file audit.jsonl --resume
```

---

## 📊 Output

Two file types:

| File          | Purpose                 |
| ------------- | ----------------------- |
| Project index | cached project metadata |
| Session file  | hits + checkpoints      |

Format → JSONL (streaming-friendly)

---

## 🧰 Post-Processing Modes

GitlabHarvester includes built-in post-processing utilities.

### Deduplicate results

```bash
gitlab-harvester -m dedup \
  --input-file session.jsonl \
  --output-file clean.jsonl
```

Options:

* `--sqlite-path file.sqlite`
* `--hash-algo blake2b|sha1|sha256`
* `--no-normalize-hits`

---

### Convert JSONL → JSON

```bash
gitlab-harvester -m convert \
  --input-file session.jsonl \
  --output-file result.json
```

Pretty print:

```bash
jq . result.json > formatted.json
```

---

## 🏗 Architecture

```
GitLab API
   ↓
Indexer
   ↓
Branch planner
   ↓
Matcher
   ↓
JSONL stream
```

Constant memory usage regardless of instance size.

---

## 🎯 Typical Use Cases

* secret discovery
* credential leaks detection
* internal audits
* redteam/pentest reconnaissance
* DevSecOps validation
* large-scale code search

---

## 🔐 Security Notice

Use only on GitLab instances where you are authorized to perform scanning.

---

## 🤝 Contributing

Pull requests and ideas welcome.

---

## 📜 License

MIT
