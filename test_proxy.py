import requests
import sys

# --- 请在这里确认您的Clash端口号 ---
PROXY_PORT = 7890
# ------------------------------------

# 我们将要测试的代理服务器地址
# Clash 同时提供 HTTP 和 SOCKS5 代理的可能性
proxies = {
   'http': f'http://127.0.0.1:{PROXY_PORT}',
   'https': f'http://127.0.0.1:{PROXY_PORT}',
}

# SOCKS5 代理的配置 (需要额外安装 `pysocks`)
# pip install pysocks
socks_proxies = {
    'http': f'socks5://127.0.0.1:{PROXY_PORT}',
    'httpss': f'socks5://127.0.0.1:{PROXY_PORT}',
}

# 我们要访问的目标
url = 'https://www.google.com'

print(f"--- 独立代理测试脚本 ---")
print(f"目标URL: {url}")
print(f"使用的代理端口: {PROXY_PORT}\n")

# --- 测试 1: 使用 HTTP 代理 ---
print(">>> 测试1: 尝试使用 HTTP 代理...")
try:
    response = requests.get(url, proxies=proxies, timeout=15)
    if response.status_code == 200:
        print("✅ 成功！HTTP 代理工作正常！")
    else:
        print(f"❌ 失败！服务器返回状态码: {response.status_code}")
except Exception as e:
    print(f"❌ 失败！发生错误: {e}")

print("-" * 20)

# --- 测试 2: 尝试使用 SOCKS5 代理 ---
# 注意: 运行此测试前，请先安装 pysocks 库
# 在命令行运行: pip install pysocks
print(">>> 测试2: 尝试使用 SOCKS5 代理...")
if 'pysocks' not in sys.modules:
    try:
        import socks
        print("Socks库已找到。")
    except ImportError:
        print("⚠️ 跳过测试: 未找到 'pysocks' 库。请运行 'pip install pysocks' 后再试。")
        sys.exit()

try:
    response = requests.get(url, proxies=socks_proxies, timeout=15)
    if response.status_code == 200:
        print("✅ 成功！SOCKS5 代理工作正常！")
    else:
        print(f"❌ 失败！服务器返回状态码: {response.status_code}")
except Exception as e:
    print(f"❌ 失败！发生错误: {e}")