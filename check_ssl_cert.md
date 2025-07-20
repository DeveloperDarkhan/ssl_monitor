# SSL Certificate Monitor

This script is designed for monitoring SSL certificates of domains from different IP addresses (essentially checking from different geo-locations).

## 📝 Description

The script allows checking SSL certificates for multiple domain aliases, providing monitoring from various geographical points.

## 📊 Input Data Format

The script accepts data in **JSON** format:

```json
{
  "example.com": [
    "cdn1.example.com", 
    "cdn2.example.com"
  ]
}
```

Where:
- **Key** - main domain 
- **Value** - array of domain aliases

## ⚙️ Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-c` | Critical threshold (days until expiration) | 14 days |
| `-w` | Warning threshold (days until expiration) | 30 days |

## 🔄 Algorithm Workflow

### 1. **IP Address Resolution**
- DNS queries are performed for each alias in the list
- All available IP addresses are extracted

### 2. **SSL Connection Check**
- SSL connection is established for each IP address
- Main domain is used for certificate validation

### 3. **Expiration Analysis**
- Time until certificate expiration is checked
- Number of days until expiration is calculated

### 4. **Result Classification**

| Status | Condition | Description |
|--------|-----------|-------------|
| 🟢 **OK** | `days > warning_days` | Certificate is valid |
| 🟡 **Warning** | `critical_days < days ≤ warning_days` | Attention required |
| 🔴 **Critical** | `days ≤ critical_days` | Urgent renewal needed |
| ❌ **Error** | Certificate issues | Technical error |

## 📤 Output Format

### ✅ Good News
```
[OK] domain.com via IP.IP.IP.IP - Certificate expires in X days
```

### ⚠️ Bad News  
```
[WARNING] domain.com via IP.IP.IP.IP - Certificate expires in X days
[CRITICAL] domain.com via IP.IP.IP.IP - Certificate expires in X days
[ERROR] domain.com via IP.IP.IP.IP - Connection failed
```

## 🚀 Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| `0` | OK | All certificates are fine |
| `1` | Warning | There are warnings |
| `2` | Critical | Critical issues found |

## 💡 Usage Examples

```bash
# Basic usage
./check_ssl_cert.sh input.json

# With custom thresholds
./check_ssl_cert.sh -w 45 -c 7 input.json

# Critical errors only
./check_ssl_cert.sh -w 0 -c 5 input.json
```

## 🌍 Geo-location Check Benefits

- **Global Availability**: checking from different points worldwide
- **CDN Monitoring**: certificate control on different servers
- **Fault Tolerance**: identifying issues in specific regions
- **Detailed Diagnostics**: complete picture of SSL infrastructure health

## 🛠️ Technical Requirements

- **bash** shell
- **openssl** utility
- **dig** or **nslookup** for DNS resolution
- **jq** for JSON parsing

## 📋 Installation

```bash
# Clone or download the script
wget https://example.com/check_ssl_cert.sh
chmod +x check_ssl_cert.sh

# Prepare input file
cat > domains.json << EOF
{
  "example.com": [
    "cdn1.example.com",
    "cdn2.example.com"
  ]
}
EOF

# Run the check
./check_ssl_cert.sh domains.json
```

## 🔍 Monitoring Integration

The script is designed for integration with monitoring systems like:

- **Nagios/Icinga**
- **Zabbix** 
- **Prometheus/Grafana**
- **Custom monitoring solutions**

Exit codes and output format follow standard monitoring conventions.

---

## 🔐 Security Note

This documentation uses generic domain names (`example.com`, `cdn1.example.com`, etc.) for security purposes. Replace them with your actual domain names when implementing the solution.