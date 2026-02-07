# 🛡️ VPN Checker & Aggregator | Automated VLESS/VMess/Trojan Validator

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/kort0881/vpn-checker-backend/run_check.yml?label=Auto-Check&style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/github/license/kort0881/vpn-checker-backend?style=for-the-badge)

**High-performance Python automation for collecting, validating, and managing VLESS, VMess, and Trojan proxy configurations.**  
Runs entirely on **GitHub Actions** (Free Tier) — zero server costs, fully automated updates every 6 hours.

---

## 📖 About the Project

This repository hosts a powerful backend script designed to aggregate VPN configurations from multiple sources, validate their connectivity (TCP/TLS/WebSocket), measure latency, and sort them by geo-location. 

It is specifically optimized for:
*   **Bypassing Censorship:** Automatically filters and verifies keys for stability.
*   **Geo-Routing:** Separates **Russian (RU)** configs (for local services like Gosuslugi/Banking) from **European (EU)** configs (for high-speed international access).
*   **Client Compatibility:** Generates subscription files compatible with **Hiddify, v2rayNG, Nekobox, Streisand**, and other Xray-core based clients.

---

## ⚡ Key Features

### 1. 🧠 Smart Validation & Filtering
*   **Real-time Ping Test:** Checks every key via socket connection (TCP/TLS).
*   **Protocol Support:** Full support for VLESS, VMess, Trojan, and Shadowsocks.
*   **Deduping:** Automatically removes duplicate keys to keep lists clean.
*   **Garbage Collector:** Filters out dead keys, local IPs, and unstable nodes (CN, IR relays).

### 2. 🌍 Advanced Geo-Sorting
*   **🇷🇺 RU_Best:** Dedicated list for Russian IP addresses. Essential for accessing region-locked services from abroad.
*   **🇪🇺 My_Euro:** Exclusive filter for high-quality European nodes (NL, DE, FI, GB, FR, SE, etc.). Automatically rejects keys from Asia, USA, or Latin America.

### 3. 📦 Smart Chunking System
*   **Crash Protection:** If the number of working keys exceeds `1000`, the script automatically splits the list into `part1.txt`, `part2.txt`, etc.
*   **Client Stability:** Prevents mobile VPN clients from freezing due to oversized subscription files.

### 4. 🚀 Performance Optimized
*   **Multi-threaded:** Checks up to **40 keys simultaneously** for maximum speed.
*   **Caching System:** Uses `history.json` to store results for 12 hours, drastically reducing API load and checking time.

---

## 🛠️ Installation & Setup Guide

Follow these steps to deploy your own instance of the VPN Checker.

### Step 1: Fork the Repository
1.  Click the **Fork** button (top right corner of this page).
2.  Name your repository (e.g., `vpn-checker-backend`).
3.  Click **Create fork**.

### Step 2: Enable Workflow Permissions (Critical!)
*Without this step, the script cannot save the checked keys.*
1.  Go to your repository **Settings**.
2.  Navigate to **Actions** → **General**.
3.  Scroll down to **Workflow permissions**.
4.  Select **Read and write permissions**.
5.  Click **Save**.

### Step 3: Configure `main.py`
Edit `main.py` directly in GitHub or your IDE. Update these variables to match your setup:

#### A. Set Your Channel Name (Line ~33)
```python
MY_CHANNEL = "@your_channel_name"
```
*This tag will be added to every key's name.*

#### B. Define Your Sources (Line ~46)
```python
URLS_RU = [ "https://raw.githubusercontent.com/..." ]  # For RU keys
URLS_MY = [ "https://raw.githubusercontent.com/..." ]  # For EU keys
```

#### C. Set Your Repo Path (Line ~260 - End of File)
**⚠️ IMPORTANT:** Scroll to the bottom and find the subscription generation block.
```python
GITHUB_USER_REPO = "your-username/your-repo-name"
```
*Change this to YOUR username and repository name. Example: `alex/vpn-checker`.*

### Step 4: Launch
1.  Go to the **Actions** tab.
2.  Select **Check VPN Keys** from the left sidebar.
3.  Click **Run workflow** → **Run workflow**.

---

## 📂 Output Files (Subscription Links)

Once the workflow finishes, check the `checked/` folder or the `subscriptions_list.txt` file.

| File Path | Description |
| :--- | :--- |
| **`checked/RU_Best/ru_white.txt`** | Verified **Russia** (RU) proxy list. |
| **`checked/My_Euro/my_euro.txt`** | Verified **Europe** (EU) proxy list. |
| **`subscriptions_list.txt`** | Master file containing direct links to all generated parts. |

*Use the raw links from `subscriptions_list.txt` in your VPN client.*

---

## ⚙️ Advanced Configuration (`main.py`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `TIMEOUT` | `5` | Socket connection timeout in seconds. |
| `THREADS` | `40` | Number of concurrent checking threads. |
| `CACHE_HOURS` | `12` | How long to trust previous check results. |
| `MAX_KEYS_TO_CHECK` | `15000` | Input limit to prevent memory overflows. |
| `EURO_CODES` | `{'NL', ...}` | Set of country codes to include in "My_Euro". |

---

## ⚖️ Legal Disclaimer

This repository is for **educational and research purposes only**. The developer is not responsible for how the scripts or the data generated by them are used. Users are solely responsible for ensuring their usage complies with local laws and regulations regarding VPN usage and internet censorship circumvention.
