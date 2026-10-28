#!/usr/bin/env bash
# Strict release gates; only synthetic credentials/configuration reach containers.
set -Eeuo pipefail
umask 077
camact_verify_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$camact_verify_root"
camact_verify_id="docker-gates-$(date -u +%Y%m%dt%H%M%Sz)-$RANDOM"
camact_verify_archive=$(python3 - "$camact_verify_root" "$camact_verify_id" <<'PY_ARCHIVE'
from datetime import datetime
from zoneinfo import ZoneInfo
import os
from pathlib import Path
import sys
root = Path(sys.argv[1])
day = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d")
archive = Path(os.environ.get("ARCHIVE_ROOT") or root / "harness/_log" / day / ("camact-docker-v1-" + sys.argv[2])).absolute()
if archive == root or (archive / "private").exists() or (archive / "verification-summary.json").exists():
    raise SystemExit("An unused explicit verification archive is required")
archive.mkdir(parents=True, exist_ok=True)
print(archive)
PY_ARCHIVE
)
mkdir -p "$camact_verify_archive/private"
printf '%s\n' "$camact_verify_id" >"$camact_verify_archive/verification-project.txt"
printf 'Docker verification archive: %s\n' "$camact_verify_archive"
camact_verify_records="$camact_verify_archive/private/stages.tsv"
: >"$camact_verify_records"
camact_verify_status=0
camact_verify_record() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}" >>"$camact_verify_records"
}
camact_verify_finish() {
  python3 - "$camact_verify_records" "$camact_verify_archive/verification-summary.json" <<'PY_REPORT'
import json
import importlib.util
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import sys
from pathlib import Path
from release.diagnostics import PREFIX
spec = importlib.util.spec_from_file_location("runner_policy", Path("scripts/verify-runner-policy.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
stages = []
diagnostics = {
    "network-disabled-offline-tests": ("camact.offline-diagnostics.v1", "offline-tests-network-disabled.json"),
    "offline-tests-in-compose": ("camact.offline-diagnostics.v1", "offline-tests-compose.json"),
    "host-sandbox-preflight": ("camact.sandbox-diagnostics.v1", "host-sandbox-preflight.json"),
    "runner-sandbox-preflight": ("camact.sandbox-diagnostics.v1", "sandbox-preflight.json"),
}
for line in Path(sys.argv[1]).read_text().splitlines():
    stage, result, code, dependency = line.split("\t")
    item = {"stage": stage, "result": result, "exit_code": int(code)}
    if dependency:
        item["dependency"] = dependency
    log = Path(sys.argv[1]).parent / (stage + ".log")
    if stage in diagnostics and log.is_file():
        schema, filename = diagnostics[stage]
        item["diagnostics_status"] = "missing"
        for entry in log.read_text(errors="replace").splitlines():
            if not entry.startswith(PREFIX):
                continue
            try:
                value = json.loads(entry[len(PREFIX):])
            except ValueError:
                continue
            if not isinstance(value, dict) or value.get("schema") != schema:
                continue
            # Only the dedicated structured emitters are public. Never copy
            # the surrounding unittest/Compose/runsc logs or exception text.
            Path(sys.argv[2]).parent.joinpath(filename).write_text(json.dumps(value, indent=2) + "\n")
            item["diagnostics_status"] = "recorded"
            item["diagnostics_file"] = filename
            if value.get("diagnostic_only") is True:
                item["diagnostic_only"] = True
                item["collector_result"] = result
                item["observed_status"] = "FAIL" if '"FAIL"' in json.dumps(value) else "UNKNOWN"
                if result == "PASS":
                    item["result"] = "COLLECTED"
            if result == "FAIL" or value.get("diagnostic_only"):
                print(json.dumps({"stage": stage, "diagnostics": value}, sort_keys=True))
        if item["diagnostics_status"] != "recorded":
            item.update(result="FAIL", exit_code=125, diagnostics_status="INCOMPLETE")
    if result == "FAIL":
        # Fixed categories help diagnose CI without exposing exception text,
        # candidate values, command arguments, host paths or credential data.
        with log.open("rb") as stream:
            observed = stream.read(2 * 1024 * 1024).lower()
        categories = {b"operation not permitted": "operation_not_permitted",
            b"permission denied": "permission_denied", b"read-only file system": "read_only_file_system",
            b"no space left on device": "no_space_left", b"cannot connect to the docker daemon": "docker_daemon_unavailable",
            b"modulenotfounderror": "python_module_missing", b"assertionerror": "assertion_failed",
            b"timed out": "timeout"}
        item["observed_error_categories"] = [code for phrase, code in categories.items() if phrase in observed]
        target = Path(sys.argv[2]).parent / "failure-logs"
        target.mkdir(exist_ok=True)
        with log.open("rb") as stream:
            raw = stream.read(2 * 1024 * 1024 + 65536)
        content = policy.sanitized(raw.decode(errors="replace"))
        (target / (stage + ".log")).write_text(content.encode()[:2 * 1024 * 1024].decode(errors="ignore"))
        item["failure_log_truncated"] = len(raw) > 2 * 1024 * 1024
    stages.append(item)
failed = next((item for item in stages if item["result"] != "PASS" and not (
    item.get("diagnostic_only") is True and item["result"] == "COLLECTED" and item.get("collector_result") == "PASS")), None)
report = {"result": "FAIL" if failed else "PASS", "stage": failed["stage"] if failed else "complete",
          "exit_code": failed["exit_code"] if failed else 0, "stages": stages,
          "synthetic_credentials_only": True, "raw_logs_uploaded": False}
Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n")
archive = Path(sys.argv[2]).parent
identity = json.loads((archive / "image-identity.json").read_text()) if (archive / "image-identity.json").is_file() else {}
identifier = (archive / "verification-project.txt").read_text().strip()
started = datetime.strptime(identifier.removeprefix("docker-gates-").rsplit("-", 1)[0], "%Y%m%dt%H%M%Sz").replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Shanghai")).isoformat()
manifest = {"schema": "camact.docker-verification.v1", "result": report["result"], "image": identity,
            "started_at": started, "method": "camact-docker-v1-production",
            "synthetic_only": True, "formal_benchmark_executed": False,
            "full_hf_validation": "not_default", "stop_resume_validation": "not_default",
            "files": ["verification-summary.json", "image-security-scan.json", "runner-policy/", "failure-logs/"]}
(archive / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
(archive / "RUN-README.md").write_text("# CamAct Docker verification\n\n"
    + "Started (Asia/Shanghai): " + started + "\n"
    + "Method: original synthetic Docker gates with actual runner policy barrier.\n"
    + "Archive: " + str(archive) + "\n"
    + "Source revision: " + str(identity.get("source_revision", os.environ.get("CAMACT_SOURCE_REVISION", "unavailable"))) + "\n"
    + "Version: " + str(identity.get("version", "unavailable")) + "\n"
    + "Reports: manifest.json, verification-summary.json, image-security-scan.json, runner-policy/, failure-logs/.\n"
    + "Raw synthetic logs/configuration stay in private/ and are excluded from uploads.\n"
    + "Canonical Benchmark, GT/rubric, Simulator, Baseline and Unified Evaluator are unchanged.\n")
print("Docker verification " + report["result"] + ": " + str(len(stages)) + " stages recorded")
PY_REPORT
}
# Run an entire stage in a fresh errexit context. Calling a function in `if`,
# `!` or `||` would disable errexit inside it and could hide a failed command.
camact_verify_run() {
  local stage=$1
  shift
  camact_verify_current_stage=$stage
  printf 'Docker verification stage: %s\n' "$stage"
  set +e
  ( set -Eeuo pipefail; "$@" ) >"$camact_verify_archive/private/$stage.log" 2>&1
  camact_verify_status=$?
  set -e
  if [[ "$camact_verify_status" == 0 ]]; then
    camact_verify_record "$stage" PASS 0
  else
    camact_verify_record "$stage" FAIL "$camact_verify_status"
    printf 'Docker verification FAIL: stage=%s exit_code=%s (raw log retained privately)\n' "$stage" "$camact_verify_status" >&2
    if [[ "$stage" == native-gvisor-runtimes-and-credential-boundary ]]; then
      printf '%s\n' 'Inspect host AppArmor audit denials and child user/mount namespace support for the non-root gVisor runner.' >&2
    fi
  fi
}
camact_verify_gate() {
  camact_verify_run "$@"
  if [[ "$camact_verify_status" != 0 ]]; then
    camact_verify_finish
    exit "$camact_verify_status"
  fi
}
camact_verify_skip() {
  camact_verify_record "$1" SKIP 125 "$2"
  printf 'Docker verification SKIP: stage=%s dependency=%s\n' "$1" "$2"
}
camact_verify_image="${CAMACT_IMAGE:-camact:local}"
camact_verify_inspect="$camact_verify_archive/private/image-inspect.json"
# Caller Compose selection/.env and model configuration must not select mounts
# or pass real credentials to synthetic verification containers.
unset COMPOSE_FILE COMPOSE_PROFILES COMPOSE_PROJECT_NAME COMPOSE_ENV_FILES COMPOSE_DISABLE_ENV_FILE
camact_verify_base=(docker compose --profile tools --env-file /dev/null --project-directory "$camact_verify_root" -f "$camact_verify_root/compose.yaml")
camact_verify_config="$camact_verify_archive/private/compose.json"
camact_verify_compose=(docker compose --env-file /dev/null --project-directory "$camact_verify_root" --project-name "$camact_verify_id" -f "$camact_verify_config")
camact_verify_runner() {
  python3 -B scripts/verify-runner-policy.py run --compose-config "$camact_verify_config" \
    --project "$camact_verify_id" --image "$camact_verify_image_id" --output "$camact_verify_archive" \
    --stage "$camact_verify_current_stage" -- "$@"
}
camact_verify_initialize() {
  ./camactctl init
  # camactctl build used to set this label before building, then execute
  # storage-init. Preserve the label without its pre-scan container side effect.
  if [[ "${CAMACT_VERIFY_SKIP_BUILD:-0}" == 0 && -z "${CAMACT_SOURCE_REVISION+x}" ]]; then
    local revision
    if revision=$(git rev-parse HEAD 2>/dev/null); then
      export CAMACT_SOURCE_REVISION="$revision"
    fi
  fi
  "${camact_verify_base[@]}" config --format json --no-env-resolution >"$camact_verify_archive/private/compose-source.json"
  python3 - "$camact_verify_archive/private" <<'PY_CONFIG'
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
source = json.loads((root / "compose-source.json").read_text())
# Preserve actual runner hardening and storage service behavior; only test
# inputs and mounts are isolated. No external .env/env_file is read.
runner = source["services"]["runner"]
storage = source["services"]["storage-init"]
for service in (runner, storage):
    service.setdefault("labels", {})["com.camact.verification"] = root.parent.joinpath("verification-project.txt").read_text().strip()
# Compose config materializes the caller project's default network name.
# Let the unique verification project own its own networks and cleanup.
source.pop("name", None)
for network in source.get("networks", {}).values():
    if not network.get("external", False):
        network.pop("name", None)
for name in ("data", "secrets"):
    (root / name).mkdir()
models = root / "models.env"
models.write_text("".join(f"{role}_MODEL=fixture-model\n{role}_BASE_URL=http://127.0.0.1\n"
                        for role in ("AGENT", "JUDGE", "SIMULATOR")))
runner["env_file"] = [{"path": str(models), "required": True}]
# No Compose-rendered environment from a caller is carried into the fixture.
runner["environment"] = {"CAMACT_DATA_ROOT": "/var/lib/camact",
    "CAMACT_OPENCLAW_TMPDIR": "/run/camact/openclaw",
    **{role + "_API_KEY_FILE": "/run/secrets/" + role.lower() + "_api_key"
       for role in ("AGENT", "JUDGE", "SIMULATOR")}}
# All synthetic services are in-process loopback fixtures. Disable external
# networking for the verification runner, including the offline cache checks.
runner.pop("networks", None)
runner["network_mode"] = "none"
for service in (runner, storage):
    for volume in service.get("volumes", []):
        if volume["target"] == "/var/lib/camact":
            volume["source"] = str(root / "data")
        elif service is storage and volume["target"] == "/secrets":
            volume["source"] = str(root / "secrets")
for name in ("agent_api_key", "judge_api_key", "simulator_api_key"):
    (root / "secrets" / name).write_text("local-fixture-only")
    source["secrets"][name] = {"file": str(root / "secrets" / name)}
(root / "compose.json").write_text(json.dumps(source) + "\n")
PY_CONFIG
  "${camact_verify_compose[@]}" config --quiet
}
camact_verify_candidate() {
  case "${CAMACT_VERIFY_SKIP_BUILD:-0}" in
    0) "${camact_verify_compose[@]}" build runner ;;
    1) docker image inspect "$camact_verify_image" --format '{{.Id}}' ;;
    *) printf '%s\n' 'CAMACT_VERIFY_SKIP_BUILD must be 0 or 1' >&2; return 2 ;;
  esac
  docker image inspect "$camact_verify_image" >"$camact_verify_inspect"
}
camact_verify_identity() {
camact_verify_image_id=$(python3 - "$camact_verify_inspect" "$camact_verify_archive/image-identity.json" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(source, list) or len(source) != 1 or not isinstance(source[0], dict):
    raise SystemExit("Docker image inspect returned an unexpected shape")
item = source[0]
image_id = item.get("Id")
if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
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
  python3 - "$camact_verify_config" "$camact_verify_archive/image-identity.json" <<'PY_PIN'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
source = json.loads(path.read_text())
identity = json.loads(Path(sys.argv[2]).read_text())
for service in source["services"].values():
    service["image"] = identity["image_id"]
source["services"]["runner"]["environment"]["CAMACT_IMAGE_DIGEST"] = identity["image_id"]
path.write_text(json.dumps(source) + "\n")
PY_PIN
}
camact_verify_scan() {
  # Scan the exact immutable candidate subsequently used for every execution.
  python3 scripts/scan-image.py --image "$camact_verify_image_id" >"$camact_verify_archive/image-security-scan.json"
}
camact_verify_gate tracked-source-security-scan python3 scripts/scan-release.py --tracked
camact_verify_run host-sandbox-preflight python3 -B scripts/gvisor-preflight.py --context host --namespace-only
camact_verify_gate compose-initialization camact_verify_initialize
camact_verify_gate candidate-build-or-inspection camact_verify_candidate
camact_verify_gate image-identity camact_verify_identity
# Subshell stage state is communicated only through the allowlisted identity.
camact_verify_image_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_id"])' "$camact_verify_archive/image-identity.json")
camact_verify_run image-security-scan camact_verify_scan
cat "$camact_verify_archive/image-security-scan.json"
if [[ "$camact_verify_status" != 0 ]]; then
  camact_verify_finish
  exit "$camact_verify_status"
fi
# All container commands, including build's former storage-init side effect,
# are below the immutable image scan and tracked source security gates.
camact_verify_run network-disabled-offline-tests docker run --rm --network=none --label "com.camact.verification=$camact_verify_id" --entrypoint python "$camact_verify_image_id" -B scripts/run-offline-tests.py
camact_verify_run network-disabled-runtime-checks docker run --rm --network=none --label "com.camact.verification=$camact_verify_id" --entrypoint python "$camact_verify_image_id" -B scripts/check-runtimes.py
camact_verify_fixture_repo="Fixture/Container-Smoke-$camact_verify_id"
camact_verify_fixture_revision='0000000000000000000000000000000000000000'
camact_verify_create_cache() {
  camact_verify_runner python -B scripts/verify-benchmark-cache.py \
    --cache-root /var/lib/camact/benchmark --repo "$camact_verify_fixture_repo" \
    --revision "$camact_verify_fixture_revision" --create
}
camact_verify_compare_cache() {
python3 - "$camact_verify_archive/private/benchmark-mount-1.json" "$camact_verify_archive/private/benchmark-mount-2.json" <<'PY'
import json
import sys
from pathlib import Path

first, second = (json.loads(Path(value).read_text(encoding="utf-8")) for value in sys.argv[1:])
if first != second:
    raise SystemExit("Benchmark cache did not survive recreated containers")
print(json.dumps({"status": "PASS", "file_count": first["file_count"],
                  "manifest_sha256": first["manifest_sha256"]}, sort_keys=True))
PY
}
camact_verify_reuse_cache() {
  camact_verify_runner python -B scripts/verify-benchmark-cache.py \
    --cache-root /var/lib/camact/benchmark --repo "$camact_verify_fixture_repo" \
    --revision "$camact_verify_fixture_revision" >"$camact_verify_archive/private/benchmark-mount-$1.json"
}
camact_verify_preflight() {
  camact_verify_runner python -B scripts/gvisor-preflight.py --context container
}
camact_verify_full_cache() {
  # Explicit opt-in only. The existing cache stays in place; all model config,
  # credentials and other persistent state remain the isolated test fixtures.
  docker compose --project-directory "$camact_verify_root" -f "$camact_verify_root/compose.yaml" \
    config --format json --no-env-resolution storage-init >"$camact_verify_archive/private/full-cache-source.json"
  python3 - "$camact_verify_config" "$camact_verify_archive/private/full-cache-source.json" "$camact_verify_archive/private/compose-full-cache.json" <<'PY_FULL'
import json
import sys
from pathlib import Path
source = json.loads(Path(sys.argv[1]).read_text())
original = json.loads(Path(sys.argv[2]).read_text())
data = next(item["source"] for item in original["services"]["storage-init"]["volumes"] if item["target"] == "/var/lib/camact")
cache = Path(data) / "benchmark"
if not cache.is_dir() or cache.is_symlink():
    raise SystemExit("Existing full benchmark cache is unavailable")
source["services"]["runner"]["volumes"].append({"type": "bind", "source": str(cache), "target": "/var/lib/camact/benchmark"})
Path(sys.argv[3]).write_text(json.dumps(source) + "\n")
PY_FULL
  local camact_verify_config="$camact_verify_archive/private/compose-full-cache.json"
  camact_verify_runner python -B -c 'import json, sys; from release.benchmark import ensure; repo,revision=sys.argv[1:]; snapshot=ensure("/var/lib/camact/benchmark", repo, revision, offline=True); marker=json.loads((snapshot.parent / "complete.json").read_text()); assert marker["repo_id"] == repo and marker["revision"] == revision and marker["file_count"] > 0; print(json.dumps({"file_count": marker["file_count"], "manifest_sha256": marker["manifest_sha256"]}, sort_keys=True))' \
    "${CAMACT_VERIFY_BENCHMARK_REPO:-Ryanjxy/CamAct-Benchmark}" "${CAMACT_VERIFY_BENCHMARK_COMMIT:-53e2f450042485dfc4a3b566de6f46988c3a5661}" \
    >"$camact_verify_archive/private/benchmark-full-offline.json"
}
camact_verify_run storage-initialization "${camact_verify_compose[@]}" --profile tools run --rm -T storage-init
camact_verify_storage_status=$camact_verify_status
if [[ "$camact_verify_storage_status" == 0 ]]; then
  camact_verify_run synthetic-benchmark-cache-creation camact_verify_create_cache
  camact_verify_cache_status=$camact_verify_status
  if [[ "$camact_verify_cache_status" == 0 ]]; then
    camact_verify_run synthetic-benchmark-cache-reuse-1 camact_verify_reuse_cache 1
    camact_verify_first_status=$camact_verify_status
    camact_verify_run synthetic-benchmark-cache-reuse-2 camact_verify_reuse_cache 2
    if [[ "$camact_verify_first_status" == 0 && "$camact_verify_status" == 0 ]]; then
      camact_verify_run synthetic-benchmark-cache-comparison camact_verify_compare_cache
    else
      camact_verify_skip synthetic-benchmark-cache-comparison synthetic-benchmark-cache-reuse
    fi
  else
    for stage in synthetic-benchmark-cache-reuse-1 synthetic-benchmark-cache-reuse-2 synthetic-benchmark-cache-comparison; do
      camact_verify_skip "$stage" synthetic-benchmark-cache-creation
    done
  fi
  if [[ "${CAMACT_VERIFY_FULL_BENCHMARK:-0}" == 1 ]]; then
    camact_verify_run full-benchmark-cache-offline-reuse camact_verify_full_cache
  fi
  camact_verify_run runner-sandbox-preflight camact_verify_preflight
  camact_verify_run ripgrep-runtime camact_verify_runner /usr/bin/rg --version
  camact_verify_run native-gvisor-runtimes-and-credential-boundary camact_verify_runner python -B scripts/check-runtimes.py --sandbox
  camact_verify_gvisor_status=$camact_verify_status
  camact_verify_run native-image-codecs camact_verify_runner python -B scripts/check-codecs.py
  camact_verify_run offline-tests-in-compose camact_verify_runner python -B scripts/run-compose-offline-tests.py --output "/var/lib/camact/scratch/$camact_verify_id/offline-tests"
  for camact_verify_harness in claude codex opencode deepseek openclaw; do
    for camact_verify_mode in single_turn multi_turn users_history; do
      stage="native-loop-$camact_verify_harness-$camact_verify_mode"
      if [[ "$camact_verify_gvisor_status" == 0 ]]; then
        camact_verify_run "$stage" camact_verify_runner python -B scripts/native-loop-smoke.py \
          --harness "$camact_verify_harness" --mode "$camact_verify_mode" \
          --output "/var/lib/camact/scratch/$camact_verify_id/$camact_verify_harness-$camact_verify_mode"
      else
        camact_verify_skip "$stage" native-gvisor-runtimes-and-credential-boundary
      fi
    done
  done
  camact_verify_run persistence-marker-creation camact_verify_runner python -B -c \
    'from pathlib import Path; import sys; p=Path("/var/lib/camact/checkpoints")/sys.argv[1]; p.write_text(sys.argv[1]); print("persistence marker created")' "$camact_verify_id"
  if [[ "$camact_verify_status" == 0 ]]; then
    camact_verify_run persistence-marker-recreated-container camact_verify_runner python -B -c \
      'from pathlib import Path; import sys; p=Path("/var/lib/camact/checkpoints")/sys.argv[1]; assert p.read_text()==sys.argv[1]; p.unlink(); print("recreated-container persistence PASS")' "$camact_verify_id"
  else
    camact_verify_skip persistence-marker-recreated-container persistence-marker-creation
  fi
else
  for stage in synthetic-benchmark-cache-creation synthetic-benchmark-cache-reuse-1 synthetic-benchmark-cache-reuse-2 synthetic-benchmark-cache-comparison runner-sandbox-preflight ripgrep-runtime native-gvisor-runtimes-and-credential-boundary native-image-codecs offline-tests-in-compose persistence-marker-creation persistence-marker-recreated-container; do
    camact_verify_skip "$stage" storage-initialization
  done
  if [[ "${CAMACT_VERIFY_FULL_BENCHMARK:-0}" == 1 ]]; then
    camact_verify_skip full-benchmark-cache-offline-reuse storage-initialization
  fi
  for camact_verify_harness in claude codex opencode deepseek openclaw; do
    for camact_verify_mode in single_turn multi_turn users_history; do
      camact_verify_skip "native-loop-$camact_verify_harness-$camact_verify_mode" storage-initialization
    done
  done
fi
camact_verify_run compose-project-cleanup "${camact_verify_compose[@]}" down --remove-orphans
camact_verify_finish
python3 - "$camact_verify_archive/verification-summary.json" <<'PY_EXIT'
import json
import sys
report = json.load(open(sys.argv[1]))
raise SystemExit(report["exit_code"])
PY_EXIT
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'image_id=%s\n' "$camact_verify_image_id" >>"$GITHUB_OUTPUT"
fi
printf '%s\n' 'Docker synthetic integration and image-layer scan passed. Full HF container validation and stop/resume remain required.'
