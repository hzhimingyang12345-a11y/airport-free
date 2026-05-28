# QingLong Local Tester

Note: this local tester is optional. The current simple workflow writes the GitHub-generated candidate pool directly to `v2ray_local.txt`, so you can subscribe in v2rayN, test latency there, and delete unavailable nodes with v2rayN.

Run `nodes/qinglong_update.py` in QingLong to test GitHub-generated candidates from your real local network and publish `v2ray_local.txt` through the GitHub REST API.

Recommended schedule: daily at 06:00 Asia/Shanghai, after GitHub Actions has generated `v2ray_candidates.txt`.

Cron:

```text
0 6 * * *
```

Required environment variable:

```text
GITHUB_TOKEN=ghp_xxx
```

The token needs repository contents read/write permission.

Optional environment variables:

```text
GITHUB_REPOSITORY=hzhimingyang12345-a11y/airport-free
GITHUB_BRANCH=main
CANDIDATE_PATH=v2ray_candidates.txt
CANDIDATE_URL=
OUTPUT_PATH=v2ray_local.txt
COMMIT_MESSAGE=Local Nodes Update
TEST_TIMEOUT=3
TEST_CONCURRENCY=300
MAX_OUTPUT=300
TLS_PROBE=0
XRAY_BIN=/usr/local/bin/xray
XRAY_TIMEOUT=5
XRAY_CONCURRENCY=8
XRAY_TEST_URL=http://www.gstatic.com/generate_204
```

By default, the script reads candidates through the GitHub Contents API, not `raw.githubusercontent.com`.
Set `CANDIDATE_URL` only when you want to use a raw URL fallback.

For accurate results, install Xray Core in the QingLong container and set `XRAY_BIN`.
When Xray is available, the script starts a temporary local SOCKS inbound for each node and checks whether the node can really proxy `XRAY_TEST_URL`.
If Xray is not available, the script falls back to simple TCP probing, which can produce many false positives.

QingLong command:

```bash
python3 nodes/qinglong_update.py
```

Final subscription:

```text
https://raw.githubusercontent.com/hzhimingyang12345-a11y/airport-free/main/v2ray_local.txt
```
