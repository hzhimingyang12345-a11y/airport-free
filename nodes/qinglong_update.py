import asyncio
import base64
import binascii
import json
import os
import ssl
import sys
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import requests


DEFAULT_REPO = "hzhimingyang12345-a11y/airport-free"
DEFAULT_BRANCH = "main"
DEFAULT_CANDIDATE_URL = (
    "https://raw.githubusercontent.com/"
    f"{DEFAULT_REPO}/{DEFAULT_BRANCH}/v2ray_candidates.txt"
)
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


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


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
    parts = decoded.split("/?", 1)[0].split(":")
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


def parse_nodes(text: str, limit: int = 0) -> list[Node]:
    nodes = []
    for line in iter_subscription_lines(text):
        node = parse_node(line)
        if node:
            nodes.append(node)
            if limit and len(nodes) >= limit:
                break
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
    return f"{raw.split('#', 1)[0]}#{quote(name, safe='')}"


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


def build_subscription(nodes: list[Node]) -> str:
    lines = [rename_node(node, index + 1) for index, node in enumerate(nodes)]
    return b64encode_text("\n".join(lines)) + "\n"


def github_headers(token: str) -> dict:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "qinglong-v2ray-local-updater",
    }


def get_existing_sha(repo: str, path: str, branch: str, token: str) -> str | None:
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    response = requests.get(url, headers=github_headers(token), params={"ref": branch}, timeout=20)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    data = response.json()
    return data.get("sha")


def update_github_file(repo: str, branch: str, path: str, content: str, token: str, message: str) -> None:
    sha = get_existing_sha(repo, path, branch, token)
    payload = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "branch": branch,
    }
    if sha:
        payload["sha"] = sha

    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    response = requests.put(url, headers=github_headers(token), json=payload, timeout=30)
    if response.status_code == 422 and "sha" in payload:
        eprint("remote file changed while updating; refreshing sha and retrying once")
        payload["sha"] = get_existing_sha(repo, path, branch, token)
        response = requests.put(url, headers=github_headers(token), json=payload, timeout=30)
    response.raise_for_status()


async def main() -> int:
    repo = os.getenv("GITHUB_REPOSITORY", DEFAULT_REPO)
    branch = os.getenv("GITHUB_BRANCH", DEFAULT_BRANCH)
    candidate_url = os.getenv("CANDIDATE_URL", DEFAULT_CANDIDATE_URL)
    output_path = os.getenv("OUTPUT_PATH", "v2ray_local.txt")
    commit_message = os.getenv("COMMIT_MESSAGE", "Local Nodes Update")
    token = os.getenv("GITHUB_TOKEN", "").strip()
    timeout = env_float("TEST_TIMEOUT", 3.0)
    concurrency = env_int("TEST_CONCURRENCY", 300)
    max_output = env_int("MAX_OUTPUT", 300)
    limit = env_int("INPUT_LIMIT", 0)
    tls_probe = os.getenv("TLS_PROBE", "0").lower() in ("1", "true", "yes")

    if not token:
        eprint("missing GITHUB_TOKEN environment variable")
        return 2

    eprint(f"fetch candidates: {candidate_url}")
    response = requests.get(candidate_url, timeout=30)
    response.raise_for_status()

    nodes = parse_nodes(response.text, limit=limit)
    eprint(f"candidate nodes: {len(nodes)}")

    alive = await test_nodes(nodes, timeout=timeout, concurrency=concurrency, tls_probe=tls_probe)
    alive = alive[:max_output]
    eprint(f"local alive nodes: {len(alive)}")

    if not alive:
        raise RuntimeError("no alive nodes found; refusing to overwrite remote subscription")

    subscription = build_subscription(alive)
    update_github_file(repo, branch, output_path, subscription, token, commit_message)
    eprint(f"updated GitHub file: {repo}/{output_path} on {branch}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        eprint("interrupted")
        raise SystemExit(130)
    except Exception as exc:
        eprint(f"failed: {exc}")
        raise SystemExit(1)
