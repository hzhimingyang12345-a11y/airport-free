import asyncio
import base64
import binascii
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import requests


DEFAULT_REPO = "hzhimingyang12345-a11y/airport-free"
DEFAULT_BRANCH = "main"
DEFAULT_CANDIDATE_PATH = "v2ray_candidates.txt"
DEFAULT_CANDIDATE_URL = (
    "https://raw.githubusercontent.com/"
    f"{DEFAULT_REPO}/{DEFAULT_BRANCH}/{DEFAULT_CANDIDATE_PATH}"
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


def bool_param(value: str) -> bool:
    return str(value).lower() in ("1", "true", "yes")


def parsed_query(raw: str) -> dict:
    try:
        return dict(parse_qsl(urlsplit(raw).query, keep_blank_values=True))
    except ValueError:
        return {}


def xray_stream_settings(node: Node, params: dict) -> dict:
    network = node.network or "tcp"
    security = node.security if node.security in ("tls", "reality") else "none"
    stream = {
        "network": network,
        "security": security,
    }

    host = params.get("host") or params.get("authority") or node.sni
    path = params.get("path") or "/"
    if network == "ws":
        stream["wsSettings"] = {
            "path": path,
            "headers": {"Host": host} if host else {},
        }
    elif network == "grpc":
        service_name = params.get("serviceName") or params.get("service") or path.strip("/")
        stream["grpcSettings"] = {"serviceName": service_name}
    elif network in ("h2", "http"):
        stream["httpSettings"] = {
            "path": path,
            "host": [host] if host else [],
        }

    server_name = params.get("sni") or params.get("peer") or host or node.host
    if security == "tls":
        stream["tlsSettings"] = {
            "serverName": server_name,
            "allowInsecure": bool_param(params.get("allowInsecure") or params.get("insecure") or "0"),
            "fingerprint": params.get("fp") or "chrome",
        }
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": server_name,
            "fingerprint": params.get("fp") or "chrome",
            "publicKey": params.get("pbk") or params.get("publicKey") or "",
            "shortId": params.get("sid") or params.get("shortId") or "",
            "spiderX": params.get("spx") or params.get("spiderX") or "",
        }

    return stream


def vmess_outbound(raw: str) -> dict | None:
    decoded = b64decode_text(raw[len("vmess://") :])
    if not decoded:
        return None
    try:
        data = json.loads(decoded)
        host = str(data.get("add") or "").strip()
        port = int(data.get("port"))
        user_id = str(data.get("id") or "").strip()
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not host or not user_id:
        return None

    node = parse_vmess(raw)
    if not node:
        return None
    params = {
        "host": data.get("host") or "",
        "path": data.get("path") or "",
        "sni": data.get("sni") or "",
    }
    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [
                        {
                            "id": user_id,
                            "alterId": int(data.get("aid") or 0),
                            "security": data.get("scy") or "auto",
                        }
                    ],
                }
            ]
        },
        "streamSettings": xray_stream_settings(node, params),
    }


def url_outbound(node: Node) -> dict | None:
    try:
        parsed = urlsplit(node.raw)
    except ValueError:
        return None
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    user = parsed.username or ""
    if not user:
        return None

    if node.scheme == "vless":
        user_config = {
            "id": user,
            "encryption": params.get("encryption") or "none",
        }
        if params.get("flow"):
            user_config["flow"] = params["flow"]
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": node.host,
                        "port": node.port,
                        "users": [user_config],
                    }
                ]
            },
            "streamSettings": xray_stream_settings(node, params),
        }

    if node.scheme == "trojan":
        return {
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": node.host,
                        "port": node.port,
                        "password": user,
                    }
                ]
            },
            "streamSettings": xray_stream_settings(node, params),
        }

    return None


def build_xray_outbound(node: Node) -> dict | None:
    if node.scheme == "vmess":
        return vmess_outbound(node.raw)
    if node.scheme in ("vless", "trojan"):
        return url_outbound(node)
    return None


def socks5_http_probe(port: int, test_url: str, timeout: float) -> bool:
    parsed = urlsplit(test_url)
    host = parsed.hostname
    if not host:
        return False
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            return False

        host_bytes = host.encode("idna")
        request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")
        sock.sendall(request)
        reply = sock.recv(10)
        if len(reply) < 2 or reply[1] != 0:
            return False

        http = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: qinglong-v2ray-local-updater\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        sock.sendall(http)
        response = sock.recv(128)
    return b"HTTP/1." in response and any(code in response[:32] for code in (b" 204 ", b" 200 ", b" 301 ", b" 302 "))


async def xray_probe(node: Node, xray_bin: str, test_url: str, timeout: float) -> Node | None:
    outbound = build_xray_outbound(node)
    if not outbound:
        return None

    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [outbound],
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as file:
        json.dump(config, file, ensure_ascii=False)
        config_path = file.name

    process = None
    start = time.perf_counter()
    try:
        process = subprocess.Popen(
            [xray_bin, "run", "-config", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(0.35)
        if process.poll() is not None:
            return None
        ok = await asyncio.to_thread(socks5_http_probe, port, test_url, timeout)
        if not ok:
            return None
        node.latency_ms = (time.perf_counter() - start) * 1000
        return node
    except (OSError, asyncio.TimeoutError, ValueError):
        return None
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
        try:
            os.unlink(config_path)
        except OSError:
            pass


async def xray_test_nodes(nodes: list[Node], xray_bin: str, test_url: str, timeout: float, concurrency: int, max_output: int) -> list[Node]:
    semaphore = asyncio.Semaphore(concurrency)
    alive = []

    async def run(node: Node) -> Node | None:
        async with semaphore:
            return await xray_probe(node, xray_bin, test_url, timeout)

    tasks = [asyncio.create_task(run(node)) for node in nodes if build_xray_outbound(node)]
    for task in asyncio.as_completed(tasks):
        result = await task
        if result:
            alive.append(result)
            eprint(f"xray alive: {len(alive)} {result.host}:{result.port} {int(result.latency_ms)}ms")
            if len(alive) >= max_output:
                for pending in tasks:
                    if not pending.done():
                        pending.cancel()
                break

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


def get_github_file(repo: str, path: str, branch: str, token: str) -> str:
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    response = requests.get(url, headers=github_headers(token), params={"ref": branch}, timeout=30)
    response.raise_for_status()
    data = response.json()
    content = data.get("content", "")
    encoding = data.get("encoding", "")
    if encoding != "base64" or not content:
        raise RuntimeError(f"unexpected GitHub content response for {path}")
    return base64.b64decode(content).decode("utf-8", errors="ignore")


def fetch_candidates(repo: str, path: str, branch: str, token: str, raw_url: str = "") -> str:
    try:
        eprint(f"fetch candidates via GitHub API: {repo}/{path}@{branch}")
        return get_github_file(repo, path, branch, token)
    except requests.RequestException as exc:
        if not raw_url:
            raise
        eprint(f"GitHub API fetch failed, fallback to raw URL: {exc}")

    response = requests.get(raw_url, timeout=30)
    response.raise_for_status()
    return response.text


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
    candidate_path = os.getenv("CANDIDATE_PATH", DEFAULT_CANDIDATE_PATH)
    candidate_url = os.getenv("CANDIDATE_URL", "")
    output_path = os.getenv("OUTPUT_PATH", "v2ray_local.txt")
    commit_message = os.getenv("COMMIT_MESSAGE", "Local Nodes Update")
    token = os.getenv("GITHUB_TOKEN", "").strip()
    timeout = env_float("TEST_TIMEOUT", 3.0)
    concurrency = env_int("TEST_CONCURRENCY", 300)
    max_output = env_int("MAX_OUTPUT", 300)
    limit = env_int("INPUT_LIMIT", 0)
    tls_probe = os.getenv("TLS_PROBE", "0").lower() in ("1", "true", "yes")
    xray_bin = os.getenv("XRAY_BIN", "").strip() or shutil.which("xray") or shutil.which("xray.exe") or ""
    xray_timeout = env_float("XRAY_TIMEOUT", timeout)
    xray_concurrency = env_int("XRAY_CONCURRENCY", 8)
    xray_test_url = os.getenv("XRAY_TEST_URL", "http://www.gstatic.com/generate_204")

    if not token:
        eprint("missing GITHUB_TOKEN environment variable")
        return 2

    candidates_text = fetch_candidates(repo, candidate_path, branch, token, candidate_url)

    nodes = parse_nodes(candidates_text, limit=limit)
    eprint(f"candidate nodes: {len(nodes)}")

    if xray_bin:
        eprint(f"use xray real proxy test: {xray_bin}")
        alive = await xray_test_nodes(
            nodes,
            xray_bin=xray_bin,
            test_url=xray_test_url,
            timeout=xray_timeout,
            concurrency=xray_concurrency,
            max_output=max_output,
        )
    else:
        eprint("xray not found; fallback to TCP probe, results may include false positives")
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
