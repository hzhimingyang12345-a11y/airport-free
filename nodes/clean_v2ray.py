import argparse
import asyncio
import base64
import binascii
import ipaddress
import json
import socket
import sys
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import requests


SUPPORTED_SCHEMES = ("vmess", "vless", "ss", "ssr", "trojan", "hysteria", "hy2")
URL_SCHEMES = ("vless", "trojan", "hysteria", "hy2")
GEO_BATCH_SIZE = 100


@dataclass
class Node:
    raw: str
    scheme: str
    host: str
    port: int
    resolved_ip: str | None = None
    geo_code: str = "UN"

    @property
    def endpoint_key(self) -> str:
        host = self.resolved_ip or self.host.lower()
        return f"{host}:{self.port}"


def eprint(*args):
    print(*args, file=sys.stderr)


def add_base64_padding(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def b64decode_text(value: str) -> str | None:
    try:
        normalized = add_base64_padding(value.strip().replace("-", "+").replace("_", "/"))
        return base64.b64decode(normalized, validate=False).decode("utf-8", errors="ignore")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def b64encode_text(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def is_probably_base64_subscription(text: str) -> bool:
    compact = "".join(text.split())
    if not compact or len(compact) < 24:
        return False
    decoded = b64decode_text(compact)
    return bool(decoded and any(f"{scheme}://" in decoded for scheme in SUPPORTED_SCHEMES))


def iter_subscription_lines(text: str) -> Iterable[str]:
    candidates = [text]
    if is_probably_base64_subscription(text):
        decoded = b64decode_text("".join(text.split()))
        if decoded:
            candidates.append(decoded)

    seen = set()
    for candidate in candidates:
        for line in candidate.splitlines():
            line = line.strip()
            if not line or line in seen:
                continue
            if line.split("://", 1)[0].lower() in SUPPORTED_SCHEMES:
                seen.add(line)
                yield line


def parse_vmess(raw: str) -> Node | None:
    payload = raw[len("vmess://") :]
    decoded = b64decode_text(payload)
    if not decoded:
        return None

    try:
        data = json.loads(decoded)
        host = str(data.get("add") or "").strip()
        port = int(data.get("port"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None

    if not host or not (0 < port < 65536):
        return None
    return Node(raw=raw, scheme="vmess", host=host, port=port)


def parse_url_node(raw: str, scheme: str) -> Node | None:
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not host or not port or not (0 < port < 65536):
        return None
    return Node(raw=raw, scheme=scheme, host=host, port=port)


def parse_ss(raw: str) -> Node | None:
    try:
        parsed = urlsplit(raw)
        if parsed.hostname and parsed.port:
            return Node(raw=raw, scheme="ss", host=parsed.hostname, port=parsed.port)
    except ValueError:
        pass

    body = raw[len("ss://") :].split("#", 1)[0].split("?", 1)[0]
    decoded = b64decode_text(body)
    if not decoded or "@" not in decoded:
        return None

    server = decoded.rsplit("@", 1)[1]
    if ":" not in server:
        return None
    host, port_text = server.rsplit(":", 1)

    try:
        port = int(port_text)
    except ValueError:
        return None

    if not host or not (0 < port < 65536):
        return None
    return Node(raw=raw, scheme="ss", host=host.strip("[]"), port=port)


def parse_ssr(raw: str) -> Node | None:
    decoded = b64decode_text(raw[len("ssr://") :])
    if not decoded:
        return None

    main = decoded.split("/?", 1)[0]
    parts = main.split(":")
    if len(parts) < 2:
        return None

    host = parts[0]
    try:
        port = int(parts[1])
    except ValueError:
        return None

    if not host or not (0 < port < 65536):
        return None
    return Node(raw=raw, scheme="ssr", host=host.strip("[]"), port=port)


def parse_node(raw: str) -> Node | None:
    scheme = raw.split("://", 1)[0].lower()
    if scheme == "vmess":
        return parse_vmess(raw)
    if scheme == "ss":
        return parse_ss(raw)
    if scheme == "ssr":
        return parse_ssr(raw)
    if scheme in URL_SCHEMES:
        return parse_url_node(raw, scheme)
    return None


async def resolve_node(node: Node, timeout: float) -> Node:
    if is_ip_address(node.host):
        node.resolved_ip = strip_ipv6_brackets(node.host)
        return node

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(node.host, node.port, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError, socket.gaierror):
        return node

    for family, _, _, _, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6):
            node.resolved_ip = sockaddr[0]
            return node
    return node


def strip_ipv6_brackets(host: str) -> str:
    return host.strip().strip("[]")


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(strip_ipv6_brackets(host))
        return True
    except ValueError:
        return False


async def resolve_all(nodes: list[Node], timeout: float, concurrency: int) -> list[Node]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run(node: Node) -> Node:
        async with semaphore:
            return await resolve_node(node, timeout)

    return await asyncio.gather(*(run(node) for node in nodes))


async def tcp_ping(node: Node, timeout: float) -> Node | None:
    target = node.resolved_ip or node.host
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, node.port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        reader.feed_eof()
        return node
    except (OSError, asyncio.TimeoutError, ValueError):
        return None


async def tcp_filter(nodes: list[Node], timeout: float, concurrency: int) -> list[Node]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run(node: Node) -> Node | None:
        async with semaphore:
            return await tcp_ping(node, timeout)

    results = await asyncio.gather(*(run(node) for node in nodes))
    return [node for node in results if node is not None]


def dedupe_by_endpoint(nodes: Iterable[Node]) -> list[Node]:
    seen = set()
    unique = []
    for node in nodes:
        key = node.endpoint_key
        if key in seen:
            continue
        seen.add(key)
        unique.append(node)
    return unique


def country_flag(code: str) -> str:
    code = (code or "UN").upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(ord(char) + 127397) for char in code)


def fetch_geo_map(ips: Iterable[str], timeout: float) -> dict[str, str]:
    unique_ips = []
    seen = set()
    for ip in ips:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        unique_ips.append(ip)

    geo = {}
    fields = "status,countryCode,query"
    url = f"http://ip-api.com/batch?fields={fields}"

    for start in range(0, len(unique_ips), GEO_BATCH_SIZE):
        batch = unique_ips[start : start + GEO_BATCH_SIZE]
        try:
            response = requests.post(url, json=batch, timeout=timeout)
            response.raise_for_status()
            rows = response.json()
        except (requests.RequestException, ValueError):
            continue

        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            query = row.get("query")
            code = row.get("countryCode")
            if row.get("status") == "success" and query and code:
                geo[str(query)] = str(code).upper()

    return geo


def rename_vmess(raw: str, name: str) -> str:
    decoded = b64decode_text(raw[len("vmess://") :])
    if not decoded:
        return raw
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        return raw
    data["ps"] = name
    encoded = b64encode_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    return f"vmess://{encoded}"


def rename_url_node(raw: str, name: str) -> str:
    base = raw.split("#", 1)[0]
    return f"{base}#{quote(name, safe='')}"


def rename_ssr(raw: str, name: str) -> str:
    decoded = b64decode_text(raw[len("ssr://") :])
    if not decoded:
        return raw

    main, sep, query = decoded.partition("/?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    params["remarks"] = b64encode_text(name).rstrip("=")
    rebuilt = f"{main}{sep}{urlencode(params)}" if sep else f"{main}/?{urlencode(params)}"
    return f"ssr://{b64encode_text(rebuilt).rstrip('=')}"


def rename_node(node: Node, name: str) -> str:
    if node.scheme == "vmess":
        return rename_vmess(node.raw, name)
    if node.scheme == "ssr":
        return rename_ssr(node.raw, name)
    if node.scheme in ("vless", "trojan", "ss", "hysteria", "hy2"):
        return rename_url_node(node.raw, name)
    return node.raw


def normalize_and_rename(nodes: list[Node], geo_timeout: float) -> list[str]:
    geo_map = fetch_geo_map((node.resolved_ip or node.host for node in nodes), geo_timeout)
    counters: dict[str, int] = {}
    renamed = []

    for node in nodes:
        code = geo_map.get(node.resolved_ip or node.host, "UN")
        node.geo_code = code
        counters[code] = counters.get(code, 0) + 1
        name = f"{country_flag(code)}{code}_{counters[code]:02d}"
        renamed.append(rename_node(node, name))

    return renamed


def read_nodes(path: str) -> list[Node]:
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        text = file.read()

    parsed = []
    for line in iter_subscription_lines(text):
        node = parse_node(line)
        if node:
            parsed.append(node)
    return parsed


def write_subscription(path: str, nodes: list[str]) -> None:
    payload = "\n".join(nodes)
    encoded = b64encode_text(payload)
    with open(path, "w", encoding="utf-8", newline="\n") as file:
        file.write(encoded)
        file.write("\n")


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Clean V2Ray subscription nodes with endpoint dedupe, TCP ping, geo rename, and Base64 output."
    )
    parser.add_argument("--input", default="v2ray.txt", help="Raw node file to read.")
    parser.add_argument("--output", default="v2ray.txt", help="Base64 subscription file to write.")
    parser.add_argument("--timeout", type=float, default=3.0, help="TCP/connect timeout in seconds.")
    parser.add_argument("--geo-timeout", type=float, default=8.0, help="IP geo API timeout in seconds.")
    parser.add_argument("--concurrency", type=positive_int, default=300, help="Concurrent DNS/TCP checks.")
    parser.add_argument("--limit", type=positive_int, help="Optional limit for local testing.")
    return parser


async def async_main(args: argparse.Namespace) -> int:
    parsed_nodes = read_nodes(args.input)
    if args.limit:
        parsed_nodes = parsed_nodes[: args.limit]
    eprint(f"parsed nodes: {len(parsed_nodes)}")

    resolved_nodes = await resolve_all(parsed_nodes, args.timeout, args.concurrency)
    unique_nodes = dedupe_by_endpoint(resolved_nodes)
    eprint(f"unique endpoints: {len(unique_nodes)}")

    alive_nodes = await tcp_filter(unique_nodes, args.timeout, args.concurrency)
    eprint(f"tcp alive nodes: {len(alive_nodes)}")

    renamed_nodes = normalize_and_rename(alive_nodes, args.geo_timeout)
    write_subscription(args.output, renamed_nodes)
    eprint(f"written nodes: {len(renamed_nodes)} -> {args.output}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        eprint("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
