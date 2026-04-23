
# Web Application Firewall (WAF) - Deep Packet Inspection Engine

This project is a functional **Layer 7 Web Application Firewall** built to intercept and analyze HTTP/HTTPS traffic. Developed as a collaborative cybersecurity project, it focuses on protecting web applications from common vulnerabilities and advanced structural attacks by inspecting traffic before it reaches the backend logic.



## Overview
Most firewalls operate at the network layer, but this WAF uses **Middleware Architecture** to perform **Deep Packet Inspection (DPI)** at the application layer. It acts as a security gatekeeper, decoding payloads and validating request structures in real-time.

---

##  Key Security Features

### 1. Deep Packet Inspection (DPI)
The engine doesn't just look at the URL; it inspects the **Request Line, Headers, and Body**. 
* **The Golden Rule:** It automatically decodes URL-encoded payloads (e.g., turning `%3Cscript%3E` back into `<script>`) before scanning, ensuring hackers cannot hide malicious code behind encoding.

### 2. Attack Signature Detection (Regex Engine)
We implemented custom Regular Expression signatures to identify and block:
* **SQL Injection (SQLi):** Detection of `UNION SELECT`, `1=1`, and comment-based bypasses.
* **Cross-Site Scripting (XSS):** Blocking of `<script>` tags, `onerror` events, and `javascript:` URIs.
* **Directory Traversal:** Monitoring for `../` and access to sensitive system files like `/etc/passwd`.
* **Command Injection:** Blocking system-level operators like `;`, `&&`, and `|`.

### 3. Structural & Protocol Defense
* **Anti-Smuggling:** Protects against **HTTP Request Smuggling** (CL.TE/TE.CL desync) by dropping requests with conflicting `Content-Length` and `Transfer-Encoding` headers.
* **Host Header Validation:** A strict whitelist ensures the `Host` header matches the intended domain, preventing Host Header Injection.
* **Payload Size Enforcement:** Blocks potential Denial of Service (DoS) or Buffer Overflow attempts by enforcing strict `MAX_CONTENT_LENGTH` limits.

### 4. Client Reputation & Filtering
* **Bot Mitigation:** Blocks traffic from known automated hacking tools (e.g., `sqlmap`, `nikto`) via User-Agent filtering.
* **Access Control:** Restricts dangerous HTTP methods (`DELETE`, `PUT`) to users with verified administrative headers.

---

## 🛠️ Tech Stack
* **Language:** Python 3.x
* **Framework:** Flask (Middleware Implementation)
* **Libraries:** `re` (Pattern Matching), `urllib.parse` (Payload Decoding)

---

## 📥 How to Use

### 1. Installation
```bash
pip install Flask
```

### 2. Run the Engine
```bash
python waf.py
```

### 3. Testing with `curl`
You can simulate attacks in your terminal to see the WAF in action:

* **Test XSS Detection:**
  `curl "http://localhost:8080/?q=<script>alert(1)</script>"`
* **Test SQLi in Body:**
  `curl -X POST http://localhost:8080/ -d "user=admin'--"`
* **Test Request Smuggling:**
  `curl -H "Content-Length: 4" -H "Transfer-Encoding: chunked" http://localhost:8080/`

---

## 👥 Team Collaboration
This project was developed as a team effort. We utilized **Git** and **GitHub** to manage version control, following a professional workflow of branching, code commits, and peer-reviewed pull requests.

* **Lead Developers:** Chintha Jayanth & Vasipalli Chethan

---

## ⚠️ Disclaimer
This project is for **educational purposes only**. It was designed to demonstrate the principles of web security and deep packet inspection. For production environments, always use industry-standard solutions alongside custom security layers.

---
**Secure your code. Protect your users. Happy Hacking!** 🛡️
