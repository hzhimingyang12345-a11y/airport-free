# QingLong Local Tester

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
```

By default, the script reads candidates through the GitHub Contents API, not `raw.githubusercontent.com`.
Set `CANDIDATE_URL` only when you want to use a raw URL fallback.

QingLong command:

```bash
python3 nodes/qinglong_update.py
```

Final subscription:

```text
https://raw.githubusercontent.com/hzhimingyang12345-a11y/airport-free/main/v2ray_local.txt
```
