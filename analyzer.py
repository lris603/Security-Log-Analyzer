import re
import sys
from collections import Counter

# 定义常见的 Web 攻击特征正则表达式（结合你的 Wireshark 抓包经验）
ATTACK_PATTERNS = {
    "SQL Injection": re.compile(r"(?i)(union\s+select|or\s+['\"]?1['\"]?\s*=\s*['\"]?1|%27|\')"),
    "XSS": re.compile(r"(?i)(<script>|%3Cscript%3E|alert\()"),
    "Path Traversal": re.compile(r"(\.\./|%2e%2e%2f)"),
    "Command Injection": re.compile(r"(;|\||&&)\s*(cat|ls|whoami|bash)")
}

def analyze_log(filepath):
    print(f"[*] 正在分析日志文件: {filepath}\n")
    alert_count = 0
    attacker_ips = Counter()

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                for attack_type, pattern in ATTACK_PATTERNS.items():
                    if pattern.search(line):
                        alert_count += 1
                        # 提取日志中的 IP 地址 (假设日志格式第一段是 IP)
                        ip_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                        ip = ip_match.group(1) if ip_match else "Unknown IP"
                        attacker_ips[ip] += 1
                        
                        # 打印告警信息（终端会显示为红色）
                        print(f"\033[91m[!] 发现攻击! 类型: {attack_type}\033[0m")
                        print(f"    - 攻击者 IP: {ip}")
                        print(f"    - 原始请求: {line.strip()[:100]}...\n")
                        break # 一条日志匹配到一个攻击就跳出，防止重复告警
        
        print("="*40)
        print(f"[*] 分析完成！共发现 {alert_count} 次恶意请求。")
        if attacker_ips:
            print("[*] 攻击者 TOP 排名 (IP: 攻击次数):")
            for ip, count in attacker_ips.most_common():
                print(f"    - {ip}: {count} 次")
                
    except FileNotFoundError:
        print(f"[-] 找不到文件: {filepath}，请检查路径是否正确。")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python3 analyzer.py <日志文件路径>")
        print("示例: python3 analyzer.py test_access.log")
    else:
        analyze_log(sys.argv[1])
