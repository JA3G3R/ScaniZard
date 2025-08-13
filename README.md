# Scanizard

**Scanizard** is a security-focused, AI-powered static analysis tool designed to detect vulnerabilities and misconfigurations in Infrastructure-as-Code (IaC) and automation workflows.  
It supports a wide range of declarative formats, including:

- Terraform  
- GitHub Actions  
- AWS CloudFormation  
- Kubernetes YAMLs  

---

## 🚀 Features

### **Risk Detection Engine**

Scanizard uses a **hybrid scanning engine** combining:

#### **Static Rule-Based Scanners**
Detects common security flaws such as:
- Public S3 buckets  
- Over-permissive IAM roles  
- Open security groups  
- Missing encryption  
- Unsafe shell commands (`curl | bash`, `eval`, etc.)  
- Hardcoded secrets or credential leaks  
- Dangerous or untrusted GitHub Actions (`uses: someone/unknown@latest`)  

#### **LLM-Backed Contextual Analysis**
Performs deeper semantic checks:
- Detecting when secrets are exposed to logs  
- Misuse of environment variables  
- Insecure conditional logic in workflows  

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/scanizard.git
cd scanizard

# Build the binary
go build -o scanizard
```

---

## 🛠 Usage

### **Scan Terraform files**
```bash
./scanizard terraform --folder ./path/to/terraform
```

### **Scan GitHub Actions workflows**
```bash
./scanizard github --folder ./.github/workflows
```

### **Scan Kubernetes manifests**
```bash
./scanizard kubernetes --folder ./manifests
```

### **Scan all supported formats in a project**
```bash
./scanizard all --folder ./project-dir
```

---

## 📄 Output

Scanizard produces **JSON** and **Markdown** reports containing:

- File & line number of the finding  
- Severity score (Low, Medium, High, Critical)  
- Risk category (Misconfiguration, Vulnerability, Secret Leak, etc.)  
- Suggested remediation steps  

Example JSON output:
```json
{
  "file": "main.tf",
  "line": 14,
  "severity": "High",
  "rule": "Overly permissive IAM policy",
  "recommendation": "Restrict actions to only those required for the resource."
}
```

---

## ⚙ Supported Commands

```bash
./scanizard terraform   # Scan Terraform configurations
./scanizard github      # Scan GitHub Actions workflows
./scanizard kubernetes  # Scan Kubernetes YAMLs
./scanizard cloudformation  # Scan AWS CloudFormation templates
./scanizard all         # Scan everything in a given folder
```

---

## 📑 Reporting & Integrations

- **Markdown & JSON reports** for human-readable and machine-parsable results  
- Integrates easily into **CI/CD pipelines**  
- Can fail builds on high/critical severity findings  

---

## 🛡 Example CI/CD Integration

### GitHub Actions:
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scanizard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Go
        uses: actions/setup-go@v4
        with:
          go-version: 1.21
      - name: Build Scanizard
        run: go build -o scanizard
      - name: Run Scan
        run: ./scanizard all --folder .
```

---

## 📜 License
MIT License — see [LICENSE](LICENSE) for details.

---

## 📬 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss your ideas.  

---

**Tip:** To view this README in **raw Markdown** on GitHub, click the **"Raw"** button above the file preview or append `?raw=true` to the URL.
