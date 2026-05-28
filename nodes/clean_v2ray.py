import argparse
import asyncio
import base64
import binascii
import ipaddress
import json
import os
import socket
import sys
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import requests


SUPPORTED_SCHEMES = ("vmess", "vless", "ss", "ssr", "trojan", "hysteria", "hy2")
URL_SCHEMES = ("vless", "trojan", "hysteria", "hy2")
CDN_PORTS = {443, 8443, 2053, 2083, 2087, 2096}
CDN_HINTS = (
    "cloudflare",
    "workers.dev",
    "pages.dev",
    "cf-ipfs.com",
    "cdn",
    "fastly",
    "akamai",
    "cloudfront",
    "azureedge",
)
GEO_BATCH_SIZE = 100


@dataclass
class Node:
    raw: str
    scheme: str
    host: str
    port: int
    network: str = "tcp"
    security: str = ""
    sni: str = ""
    path: str = ""
    user_id: str = ""
    host_header: str = ""
    plugin: str = ""
    resolved_ip: str | None = None
    geo_code: str = "UN"
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def endpoint_key(self) -> str:
        host = self.resolved_ip or self.host.lower()
        return f"{host}:{self.port}"

    @property
    def config_key(self) -> str:
        host = self.resolved_ip or self.host.lower()
        return "|".join(
            (
                self.scheme.lower(),
                host,
                str(self.port),
                self.network.lower(),
                self.security.lower(),
                self.sni.lower(),
                self.host_header.lower(),
                self.path,
                self.user_id.lower(),
                self.plugin.lower(),
            )
        )

    @property
    def feature_text(self) -> str:
        return " ".join(
            item.lower()
            for item in (self.raw, self.host, self.sni, self.path)
            if item
        )


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


def first_value(data: dict, keys: Iterable[str], default: str = "") -> str:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def parse_vmess(raw: str) -> Node | None:
    decoded = b64decode_text(raw[len("vmess://") :])
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

    network = first_value(data, ("net", "network", "type"), "tcp").lower()
    security = first_value(data, ("tls", "security"), "").lower()
    if security in ("1", "true"):
        security = "tls"
    user_id = first_value(data, ("id",), "")
    host_header = first_value(data, ("host",), "")
    sni = first_value(data, ("sni", "host", "add"), "")
    path = first_value(data, ("path",), "")
    return Node(
        raw=raw,
        scheme="vmess",
        host=host,
        port=port,
        network=network,
        security=security,
        sni=sni,
        path=path,
        user_id=user_id,
        host_header=host_header,
    )


def parse_url_node(raw: str, scheme: str) -> Node | None:
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not host or not port or not (0 < port < 65536):
        return None

    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    network = first_value(params, ("type", "network", "net"), "tcp").lower()
    security = first_value(params, ("security", "tls"), "").lower()
    if scheme in ("trojan", "hysteria", "hy2") and not security:
        security = "tls"
    user_id = parsed.username or ""
    host_header = first_value(params, ("host", "authority"), "")
    sni = first_value(params, ("sni", "peer", "host"), "")
    path = first_value(params, ("path",), "")
    return Node(
        raw=raw,
        scheme=scheme,
        host=host,
        port=port,
        network=network,
        security=security,
        sni=sni,
        path=path,
        user_id=user_id,
        host_header=host_header,
    )


def parse_ss(raw: str) -> Node | None:
    try:
        parsed = urlsplit(raw)
        if parsed.hostname and parsed.port:
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            plugin = params.get("plugin", "").lower()
            network = "ws" if "websocket" in plugin or "ws" in plugin else "tcp"
            security = "tls" if "tls" in plugin else ""
            return Node(
                raw=raw,
                scheme="ss",
                host=parsed.hostname,
                port=parsed.port,
                network=network,
                security=security,
                sni=params.get("host", ""),
                path=params.get("path", ""),
                plugin=plugin,
            )
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
    return Node(raw=raw, scheme="ss", host=host.strip("[]"), port=port, user_id=decoded.rsplit("@", 1)[0])


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
    return Node(raw=raw, scheme="ssr", host=host.strip("[]"), port=port, user_id=":".join(parts[2:]))


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


def strip_ipv6_brackets(host: str) -> str:
    return host.strip().strip("[]")


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(strip_ipv6_brackets(host))
        return True
    except ValueError:
        return False


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


async def resolve_all(nodes: list[Node], timeout: float, concurrency: int) -> list[Node]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run(node: Node) -> Node:
        async with semaphore:
            return await resolve_node(node, timeout)

    return await asyncio.gather(*(run(node) for node in nodes))


def has_cdn_hint(node: Node) -> bool:
    return any(hint in node.feature_text for hint in CDN_HINTS)


def score_node(node: Node) -> Node:
    score = 0
    reasons = []

    if node.network == "ws":
        score += 40
        reasons.append("ws")
    elif node.network in ("grpc", "h2", "httpupgrade"):
        score += 18
        reasons.append(node.network)
    elif node.network == "tcp":
        score -= 35
        reasons.append("tcp_penalty")

    if node.security in ("tls", "reality"):
        score += 35
        reasons.append(node.security)
    elif node.security:
        score += 8
        reasons.append(node.security)
    else:
        score -= 25
        reasons.append("no_tls")

    if node.network == "ws" and node.security in ("tls", "reality"):
        score += 45
        reasons.append("ws_tls")

    if node.port in CDN_PORTS:
        score += 18
        reasons.append(f"cdn_port_{node.port}")

    if has_cdn_hint(node):
        score += 35
        reasons.append("cdn_hint")

    if node.scheme in ("vless", "vmess", "trojan"):
        score += 8
        reasons.append(node.scheme)
    elif node.scheme in ("ss", "ssr") and node.network == "tcp" and not node.security:
        score -= 20
        reasons.append("plain_ss")

    node.score = score
    node.reasons = reasons
    return node


def feature_filter(nodes: Iterable[Node], min_score: int, keep_plain_tcp: bool, preserve_order: bool) -> list[Node]:
    filtered = []
    for node in nodes:
        score_node(node)
        if not keep_plain_tcp and node.network == "tcp" and node.security not in ("tls", "reality"):
            continue
        if node.score < min_score:
            continue
        filtered.append(node)
    if preserve_order:
        return filtered
    return sorted(filtered, key=lambda item: item.score, reverse=True)


def dedupe_nodes(nodes: Iterable[Node], mode: str) -> list[Node]:
    seen = set()
    unique = []
    for node in nodes:
        key = node.endpoint_key if mode == "endpoint" else node.config_key
        if key in seen:
            continue
        seen.add(key)
        unique.append(node)
    return unique


async def domestic_ping_check(node: Node, api_url: str, timeout: float) -> bool:
    if not api_url:
        return True

    payload = {
        "host": node.resolved_ip or node.host,
        "port": node.port,
        "timeout": timeout,
    }

    def request_api() -> bool:
        try:
            response = requests.post(api_url, json=payload, timeout=timeout + 2)
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError):
            return True

        if isinstance(data, dict):
            if data.get("alive") is False:
                return False
            loss = data.get("loss") or data.get("packet_loss")
            if isinstance(loss, (int, float)) and loss >= 80:
                return False
            latency = data.get("latency") or data.get("rtt")
            if isinstance(latency, (int, float)) and latency <= timeout * 1000:
                return True
        return bool(data.get("alive", True)) if isinstance(data, dict) else True

    return await asyncio.to_thread(request_api)


async def domestic_filter(nodes: list[Node], api_url: str, timeout: float, concurrency: int) -> list[Node]:
    if not api_url:
        return nodes

    semaphore = asyncio.Semaphore(concurrency)

    async def run(node: Node) -> Node | None:
        async with semaphore:
            return node if await domestic_ping_check(node, api_url, timeout) else None

    results = await asyncio.gather(*(run(node) for node in nodes))
    return [node for node in results if node is not None]


def country_flag(code: str) -> str:
    code = (code or "UN").upper()
    if len(code) != 2 or not code.isalpha():
        return "[UN]"
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
    return rename_url_node(node.raw, name)


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
        description="Build a China-friendly V2Ray candidate pool with endpoint dedupe and CDN/WS/TLS feature scoring."
    )
    parser.add_argument("--input", default="v2ray.txt", help="Raw node file to read.")
    parser.add_argument("--output", default="v2ray_candidates.txt", help="Base64 candidate subscription to write.")
    parser.add_argument("--mirror-output", help="Optional second output path, useful for keeping v2ray.txt as candidate feed.")
    parser.add_argument("--resolve-timeout", type=float, default=3.0, help="DNS resolve timeout in seconds.")
    parser.add_argument("--geo-timeout", type=float, default=8.0, help="IP geo API timeout in seconds.")
    parser.add_argument("--domestic-api", default=os.getenv("DOMESTIC_PING_API", ""), help="Optional China-side ping API URL.")
    parser.add_argument("--domestic-timeout", type=float, default=3.0, help="Domestic ping API timeout hint.")
    parser.add_argument("--concurrency", type=positive_int, default=300, help="Concurrent DNS/API checks.")
    parser.add_argument("--min-score", type=int, default=55, help="Minimum feature score to keep a node.")
    parser.add_argument("--max-candidates", type=positive_int, default=2500, help="Maximum candidate nodes to output.")
    parser.add_argument("--keep-plain-tcp", action="store_true", help="Keep low-potential plain TCP nodes.")
    parser.add_argument("--preserve-order", action="store_true", help="Preserve source order instead of sorting by feature score.")
    parser.add_argument("--dedupe-mode", choices=("config", "endpoint"), default="config", help="Use config to keep same endpoint with different SNI/path/user.")
    parser.add_argument("--limit", type=positive_int, help="Optional input limit for local testing.")
    return parser


async def async_main(args: argparse.Namespace) -> int:
    parsed_nodes = read_nodes(args.input)
    if args.limit:
        parsed_nodes = parsed_nodes[: args.limit]
    eprint(f"parsed nodes: {len(parsed_nodes)}")

    resolved_nodes = await resolve_all(parsed_nodes, args.resolve_timeout, args.concurrency)
    unique_nodes = dedupe_nodes(resolved_nodes, args.dedupe_mode)
    eprint(f"unique nodes ({args.dedupe_mode}): {len(unique_nodes)}")

    feature_nodes = feature_filter(unique_nodes, args.min_score, args.keep_plain_tcp, args.preserve_order)
    eprint(f"feature candidates: {len(feature_nodes)}")

    domestic_nodes = await domestic_filter(
        feature_nodes,
        args.domestic_api,
        args.domestic_timeout,
        min(args.concurrency, 80),
    )
    if args.domestic_api:
        eprint(f"domestic api candidates: {len(domestic_nodes)}")

    candidates = domestic_nodes[: args.max_candidates]
    renamed_nodes = normalize_and_rename(candidates, args.geo_timeout)
    write_subscription(args.output, renamed_nodes)
    if args.mirror_output:
        write_subscription(args.mirror_output, renamed_nodes)
    eprint(f"written candidates: {len(renamed_nodes)} -> {args.output}")
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
