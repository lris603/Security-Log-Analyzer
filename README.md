# Security Log Analyzer (Web日志智能分析工具)
## 目的
使用Python快速识别日志中的恶意攻击载荷，提取攻击者IP，辅助安全人员进行应急响应。
## 功能
- 基于正则表达式引擎，支持识别**SQL注入、xss、路径穿越、命令注入**等常见攻击特征。
- 自动提取并聚合攻击者真实IP，输出TOP攻击源排名。
- 终端高亮警告，适配Linux环境。
## 技术
- Python3（正则`re`库，集合`collections`）
- 结合HTTP协议与OWASP Top 10 漏洞特征（针对 `%27 OR 1=1`的拦截）
## 使用
```bash
python3 analyzer.py test_access.log
```
## 运行效果
<img width="1713" height="566" alt="demo1" src="https://github.com/user-attachments/assets/34b58cc6-f3e4-4dc4-8726-5e583ecbf3bf" />

