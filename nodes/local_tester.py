import argparse
import asyncio
import base64
import binascii
import json
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urlsplit


SUPPORTED_SCHEMES = ("vmess", "vless", "ss", "ssr", "trojan", "hysteria", "hy2")
URL_SCHEMES = ("vless", "trojan", "hysteria", "hy2")


@dataclass
class Node:
    raw: str
    scheme: str
    host: str
    port: int
    network: str = "tcp"
    security: str = ""
    sni: str = ""
    latency_ms: float = 0.0


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


def iter_subscription_lines(text: str):
    candidates = [text]
    decoded = b64decode_text("".join(text.split()))
    if decoded and any(f"{scheme}://" in decoded for scheme in SUPPORTED_SCHEMES):
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


def first_value(data: dict, keys, default: str = "") -> str:
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
    sni = first_value(data, ("sni", "host", "add"), "")
    return Node(raw=raw, scheme="vmess", host=host, port=port, network=network, security=security, sni=sni)


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
    sni = first_value(params, ("sni", "peer", "host"), "")
    return Node(raw=raw, scheme=scheme, host=host, port=port, network=network, security=security, sni=sni)


def parse_ss(raw: str) -> Node | None:
    try:
        parsed = urlsplit(raw)
        if parsed.hostname and parsed.port:
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            plugin = params.get("plugin", "").lower()
            network = "ws" if "websocket" in plugin or "ws" in plugin else "tcp"
            security = "tls" if "tls" in plugin else ""
            return Node(raw=raw, scheme="ss", host=parsed.hostname, port=parsed.port, network=network, security=security)
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
    return Node(raw=raw, scheme="ss", host=host.strip("[]"), port=port)


def parse_ssr(raw: str) -> Node | None:
    decoded = b64decode_text(raw[len("ssr://") :])
    if not decoded:
        return None
    main = decoded.split("/?", 1)[0]
    parts = main.split(":")
    if len(parts) < 2:
        return None
    try:
        port = int(parts[1])
    except ValueError:
        return None
    return Node(raw=raw, scheme="ssr", host=parts[0].strip("[]"), port=port)


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


def read_nodes(path: str) -> list[Node]:
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        text = file.read()
    nodes = []
    for line in iter_subscription_lines(text):
        node = parse_node(line)
        if node:
            nodes.append(node)
    return nodes


async def tcp_latency(node: Node, timeout: float, tls_probe: bool) -> Node | None:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(node.host, node.port),
            timeout=timeout,
        )
        if tls_probe and node.security in ("tls", "reality"):
            writer.close()
            await writer.wait_closed()
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    node.host,
                    node.port,
                    ssl=ssl_context,
                    server_hostname=node.sni or node.host,
                ),
                timeout=timeout,
            )
        writer.close()
        await writer.wait_closed()
        reader.feed_eof()
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
        return None

    node.latency_ms = (time.perf_counter() - start) * 1000
    return node


async def test_nodes(nodes: list[Node], timeout: float, concurrency: int, tls_probe: bool) -> list[Node]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run(node: Node) -> Node | None:
        async with semaphore:
            return await tcp_latency(node, timeout, tls_probe)

    results = await asyncio.gather(*(run(node) for node in nodes))
    alive = [node for node in results if node is not None]
    return sorted(alive, key=lambda item: item.latency_ms)


def rename_vmess(raw: str, name: str) -> str:
    decoded = b64decode_text(raw[len("vmess://") :])
    if not decoded:
        return raw
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        return raw
    data["ps"] = name
    return f"vmess://{b64encode_text(json.dumps(data, ensure_ascii=False, separators=(',', ':')))}"


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


def rename_node(node: Node, index: int) -> str:
    name = f"LOCAL_{index:03d}_{int(node.latency_ms)}ms"
    if node.scheme == "vmess":
        return rename_vmess(node.raw, name)
    if node.scheme == "ssr":
        return rename_ssr(node.raw, name)
    return rename_url_node(node.raw, name)


def write_subscription(path: str, nodes: list[str]) -> None:
    payload = "\n".join(nodes)
    with open(path, "w", encoding="utf-8", newline="\n") as file:
        file.write(b64encode_text(payload))
        file.write("\n")


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Locally test v2ray candidate nodes and write a final Base64 subscription.")
    parser.add_argument("--input", default="v2ray_candidates.txt", help="Candidate subscription from GitHub Actions.")
    parser.add_argument("--output", default="v2ray_local.txt", help="Final local Base64 subscription output.")
    parser.add_argument("--timeout", type=float, default=3.0, help="Local TCP/TLS timeout in seconds.")
    parser.add_argument("--concurrency", type=positive_int, default=300, help="Concurrent local probes.")
    parser.add_argument("--max-output", type=positive_int, default=300, help="Maximum alive nodes to output.")
    parser.add_argument("--tls-probe", action="store_true", help="Also perform TLS handshake for TLS nodes.")
    parser.add_argument("--limit", type=positive_int, help="Optional input limit for quick testing.")
    return parser


async def async_main(args: argparse.Namespace) -> int:
    nodes = read_nodes(args.input)
    if args.limit:
        nodes = nodes[: args.limit]
    eprint(f"candidate nodes: {len(nodes)}")

    alive = await test_nodes(nodes, args.timeout, args.concurrency, args.tls_probe)
    alive = alive[: args.max_output]
    eprint(f"local alive nodes: {len(alive)}")

    renamed = [rename_node(node, index + 1) for index, node in enumerate(alive)]
    write_subscription(args.output, renamed)
    eprint(f"written final subscription: {len(renamed)} -> {args.output}")
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
