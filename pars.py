import re
import requests
from bs4 import BeautifulSoup

def getproxy():
    url = "https://spys.one/en/socks-proxy-list/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    }

    try:
        res = requests.get(url, headers=headers, timeout=10)
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"Ошибка интернета: {e}")
        return []

    soup = BeautifulSoup(res.text, "html.parser")
    xx0_input = soup.find("input", {"name": "xx0"})
    if not xx0_input or "value" not in xx0_input.attrs:
        print("Поля сайта изменились. Пожалуйста, напишите об этом @ownerofany")
        return []

    xx0_value = xx0_input["value"]

    data = {
        "xx0": xx0_value,
        "xpp": "1",  # 0-30, 1-50, 2-100, 3-200, 4-300, 5-500 колво прокси
        "xf1": "0",
        "xf2": "0",
        "xf4": "0",
        "xf5": "2"
    }

    try:
        res = requests.post(url, headers=headers, data=data, timeout=10)
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"Ошибка интернета: {e}")
        return []

    soup = BeautifulSoup(res.text, "html.parser")
    rows = soup.find_all("tr", class_=re.compile(r"spy1x|spy1xx"))
    if not rows:
        print("Поля сайта изменились. Пожалуйста, напишите об этом @ownerofany")
        return []

    js_vars = {}
    js_code = soup.find("script", string=re.compile(r"\w+=\d+\^\w+;"))
    if js_code:
        mtc = re.findall(r"(\w+)\s*=\s*(\d+)\^(\w+);", js_code.string)
        for var, a, b in mtc:
            a = int(a)
            b_val = js_vars.get(b, 0)
            js_vars[var] = a ^ b_val
    else:
        print("Скрипт сайта изменился. Пожалуйста, напишите об этом @ownerofany")
        return []

    proxies = []
    for row in rows:
        cols = row.find_all("td")
        if not cols or len(cols) < 2:
            continue

        ip_tag = cols[0].find("font", class_="spy14")
        if not ip_tag:
            continue
        ip = ip_tag.text.strip()

        port_script = ip_tag.find_next("script")
        port = None
        if port_script:
            js_expr = port_script.string
            if js_expr:
                parts = re.findall(r"\((\w+)\^(\w+)\)", js_expr)
                port = ""
                for a, b in parts:
                    val = js_vars.get(a, 0) ^ js_vars.get(b, 0)
                    port += str(val)
                port = port.strip()

        proxy_type = cols[1].text.strip()
        country_tag = cols[3].find("font", class_="spy14")
        country = country_tag.text.strip() if country_tag else ""

        proxies.append({
            "ip": ip,
            "port": port,
            "type": proxy_type,
            "country": country
        })

    return proxies[:100]

def main():
    proxies = getproxy()
    if not proxies:
        print("Не нашёл прокси")
        return

    for p in proxies:
        print(f"{p['ip']}:{p['port']} {p['type']} {p['country']}")

if __name__ == "__main__":
    main()