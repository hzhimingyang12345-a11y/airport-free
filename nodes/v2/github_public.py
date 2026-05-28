import base64
import binascii
import requests

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
}

TIMEOUT = 20
PROTOCOLS = (
    "vmess://",
    "vless://",
    "ss://",
    "ssr://",
    "trojan://",
    "hysteria://",
    "hy2://",
)

urls = [
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",
    "https://raw.githubusercontent.com/firefoxmmx2/v2rayshare_subcription/main/subscription/vray_sub.txt",
    "https://raw.githubusercontent.com/a2470982985/getNode/main/v2ray.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/v2ray-links/v2ray-free/master/v2ray",
]


def decode_base64_text(text):
    cleaned = "".join(text.split())
    if not cleaned:
        return None

    cleaned = cleaned.replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)

    try:
        decoded = base64.b64decode(cleaned, validate=False)
        return decoded.decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return None


def iter_nodes(text):
    candidates = [text]
    decoded = decode_base64_text(text)
    if decoded:
        candidates.append(decoded)

    for candidate in candidates:
        for line in candidate.splitlines():
            line = line.strip()
            if line.startswith(PROTOCOLS):
                yield line


def main():
    seen = set()

    for url in urls:
        try:
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            response.raise_for_status()
        except requests.exceptions.RequestException:
            continue

        for node in iter_nodes(response.text):
            if node in seen:
                continue
            seen.add(node)
            print(node)


if __name__ == "__main__":
    main()
