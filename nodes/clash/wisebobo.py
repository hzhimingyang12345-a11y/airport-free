import requests


headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
}

url = "https://raw.githubusercontent.com/wisebobo/clashNodes/master/rules_clash.yaml"


try:
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()
    print(response.text)
except requests.exceptions.RequestException as exc:
    print(f"# failed to fetch wisebobo clash source: {exc}")
