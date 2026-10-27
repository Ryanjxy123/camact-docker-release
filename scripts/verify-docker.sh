#!/usr/bin/env bash
# Required integration gates on an unrestricted dedicated Docker host.
# Synthetic local model protocols only: never uses the configured model keys.
set -euo pipefail
camact_verify_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$camact_verify_root"
camact_verify_id="docker-gates-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
camact_verify_archive="$camact_verify_root/.validation/$camact_verify_id"
mkdir -p "$camact_verify_archive"
exec > >(tee "$camact_verify_archive/verification.log") 2>&1
camact_verify_image="${CAMACT_IMAGE:-camact:local}"
./camactctl init
docker compose config --quiet
case "${CAMACT_VERIFY_SKIP_BUILD:-0}" in
  0) ./camactctl build ;;
  1) docker image inspect "$camact_verify_image" --format '{{.Id}}' ;;
  *) printf '%s\n' 'CAMACT_VERIFY_SKIP_BUILD must be 0 or 1' >&2; exit 2 ;;
esac
camact_verify_inspect="$camact_verify_archive/image-inspect.json"
if ! docker image inspect "$camact_verify_image" >"$camact_verify_inspect" 2>"$camact_verify_archive/image-inspect-error.log"; then
  printf '%s\n' 'Docker image inspection failed; see the private validation archive.' >&2
  exit 1
fi
camact_verify_image_id=$(python3 - "$camact_verify_inspect" "$camact_verify_archive/image-identity.json" <<'PY'
import json
import os
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(source, list) or len(source) != 1 or not isinstance(source[0], dict):
    raise SystemExit("Docker image inspect returned an unexpected shape")
item = source[0]
image_id = item.get("Id")
if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
    raise SystemExit("Docker image has no immutable content ID")
labels = ((item.get("Config") or {}).get("Labels") or {})
version = labels.get("org.opencontainers.image.version")
revision = labels.get("org.opencontainers.image.revision")
if not isinstance(version, str) or not version or version == "<no value>":
    raise SystemExit("Docker image is missing an OCI version label")
if not isinstance(revision, str) or not revision or revision == "<no value>":
    raise SystemExit("Docker image is missing an OCI source revision label")
expected_version = os.environ.get("CAMACT_EXPECT_VERSION")
expected_revision = os.environ.get("CAMACT_EXPECT_SOURCE_REVISION")
if expected_version and version != expected_version:
    raise SystemExit("Docker image OCI version does not match the expected release")
if expected_revision and revision != expected_revision:
    raise SystemExit("Docker image OCI source revision does not match the expected source")
env = (item.get("Config") or {}).get("Env") or []
env_map = {}
for value in env:
    if isinstance(value, str) and "=" in value:
        name, content = value.split("=", 1)
        env_map[name] = content
if env_map.get("CAMACT_IMAGE_VERSION") != version or env_map.get("CAMACT_SOURCE_REVISION") != revision:
    raise SystemExit("Docker image version environment does not match OCI labels")
Path(sys.argv[2]).write_text(json.dumps({"image_id": image_id, "version": version,
    "source_revision": revision}, sort_keys=True) + "\n", encoding="utf-8")
print(image_id)
PY
)
export CAMACT_IMAGE_DIGEST="$camact_verify_image_id"
python3 scripts/scan-image.py --image "$camact_verify_image" >"$camact_verify_archive/image-security-scan.json"
camact_verify_data_dir="${CAMACT_DATA_DIR:-./.data}"
case "$camact_verify_data_dir" in
  /*) camact_verify_data_root="$camact_verify_data_dir" ;;
  *) camact_verify_data_root="$camact_verify_root/$camact_verify_data_dir" ;;
esac
camact_verify_fixture_repo="Fixture/Container-Smoke-$camact_verify_id"
camact_verify_fixture_revision='0000000000000000000000000000000000000000'
camact_verify_fixture_hash=$(python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:12])' "$camact_verify_fixture_repo")
camact_verify_fixture_dir="$camact_verify_data_root/benchmark/Fixture--Container-Smoke-$camact_verify_fixture_hash/$camact_verify_fixture_revision"
camact_verify_fixture_mount="/var/lib/camact/benchmark/Fixture--Container-Smoke-$camact_verify_fixture_hash/$camact_verify_fixture_revision"
trap 'docker compose --profile tools run --rm -T --entrypoint python storage-init -B -c '\''import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)'\'' "$camact_verify_fixture_mount" >/dev/null 2>&1 || true' EXIT
python3 - "$camact_verify_fixture_dir" "$camact_verify_fixture_repo" "$camact_verify_fixture_revision" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

directory = Path(sys.argv[1])
repo, revision = sys.argv[2:]
directory.mkdir(parents=True, exist_ok=False)
snapshot = directory / "snapshot"
snapshot.mkdir(parents=True, exist_ok=False)
data = b"camact-container-benchmark-smoke\n"
relative = "fixture/task.yaml"
path = snapshot / relative
path.parent.mkdir()
path.write_bytes(data)
digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
manifest = {"schema": "camact.benchmark-cache.v1", "repo_id": repo, "revision": revision,
            "files": {relative: {"size": len(data), "algorithm": "git-sha1", "digest": digest}}}
(directory / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
(directory / "complete.json").write_text(json.dumps({"schema": manifest["schema"], "repo_id": repo,
    "revision": revision, "file_count": 1, "total_bytes": len(data),
    "manifest_sha256": hashlib.sha256(encoded).hexdigest()}, sort_keys=True) + "\n")
PY
docker compose --profile tools run --rm -T storage-init
camact_verify_benchmark_code='import json, os; from release.benchmark import ensure; repo=os.environ["CAMACT_VERIFY_REPO"]; revision=os.environ["CAMACT_VERIFY_REVISION"]; snapshot=ensure("/var/lib/camact/benchmark", repo, revision, offline=True); marker=json.loads((snapshot.parent / "complete.json").read_text()); assert marker["repo_id"] == repo and marker["revision"] == revision and marker["file_count"] == 1; print(json.dumps({"repo_id": repo, "revision": revision, "file_count": marker["file_count"], "manifest_sha256": marker["manifest_sha256"]}, sort_keys=True))'
for camact_verify_benchmark_pass in 1 2; do
  docker compose run --rm -T --entrypoint python \
    -e CAMACT_VERIFY_REPO="$camact_verify_fixture_repo" \
    -e CAMACT_VERIFY_REVISION="$camact_verify_fixture_revision" \
    runner -B -c "$camact_verify_benchmark_code" >"$camact_verify_archive/benchmark-mount-$camact_verify_benchmark_pass.json"
done
python3 - "$camact_verify_archive/benchmark-mount-1.json" "$camact_verify_archive/benchmark-mount-2.json" <<'PY'
import json
import sys
from pathlib import Path

first, second = (json.loads(Path(value).read_text(encoding="utf-8")) for value in sys.argv[1:])
if first != second:
    raise SystemExit("Benchmark cache did not survive recreated containers")
print(json.dumps({"status": "PASS", "file_count": first["file_count"],
                  "manifest_sha256": first["manifest_sha256"]}, sort_keys=True))
PY
if [[ "${CAMACT_VERIFY_FULL_BENCHMARK:-0}" == 1 ]]; then
  camact_verify_full_repo="${CAMACT_VERIFY_BENCHMARK_REPO:-Ryanjxy/CamAct-Benchmark}"
  camact_verify_full_revision="${CAMACT_VERIFY_BENCHMARK_COMMIT:-53e2f450042485dfc4a3b566de6f46988c3a5661}"
  docker compose run --rm -T --entrypoint python \
    -e CAMACT_VERIFY_REPO="$camact_verify_full_repo" \
    -e CAMACT_VERIFY_REVISION="$camact_verify_full_revision" \
    runner -B -c 'import json, os; from release.benchmark import ensure; repo=os.environ["CAMACT_VERIFY_REPO"]; revision=os.environ["CAMACT_VERIFY_REVISION"]; snapshot=ensure("/var/lib/camact/benchmark", repo, revision, offline=True); marker=json.loads((snapshot.parent / "complete.json").read_text()); assert marker["repo_id"] == repo and marker["revision"] == revision and marker["file_count"] > 0; print(json.dumps({"repo_id": repo, "revision": revision, "file_count": marker["file_count"], "manifest_sha256": marker["manifest_sha256"]}, sort_keys=True))' \
    >"$camact_verify_archive/benchmark-full-offline.json"
fi
docker compose run --rm -T --entrypoint /usr/bin/rg runner --version
docker compose run --rm -T --entrypoint python runner -B scripts/check-runtimes.py --sandbox
docker compose run --rm -T --entrypoint python runner -B scripts/check-codecs.py
docker compose run --rm -T --entrypoint python runner -B scripts/run-offline-tests.py
for camact_verify_harness in claude codex opencode deepseek openclaw; do
  for camact_verify_mode in single_turn multi_turn users_history; do
    docker compose run --rm -T --entrypoint python runner -B scripts/native-loop-smoke.py \
      --harness "$camact_verify_harness" --mode "$camact_verify_mode" \
      --output "/var/lib/camact/scratch/$camact_verify_id/$camact_verify_harness-$camact_verify_mode"
  done
done
# Two separately created containers must observe identical persisted bytes.
docker compose run --rm -T --entrypoint python runner -B -c \
  'from pathlib import Path; import sys; p=Path("/var/lib/camact/checkpoints")/sys.argv[1]; p.write_text(sys.argv[1]); print("persistence marker created")' "$camact_verify_id"
docker compose run --rm -T --entrypoint python runner -B -c \
  'from pathlib import Path; import sys; p=Path("/var/lib/camact/checkpoints")/sys.argv[1]; assert p.read_text()==sys.argv[1]; p.unlink(); print("recreated-container persistence PASS")' "$camact_verify_id"
python3 scripts/scan-release.py --tracked
printf '%s\n' 'Docker execution gates passed. Full HF completion, image-layer scan, and final publication audit are separate required gates.'
