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
./camactctl init
docker compose config --quiet
case "${CAMACT_VERIFY_SKIP_BUILD:-0}" in
  0) ./camactctl build ;;
  1) docker image inspect "${CAMACT_IMAGE:-camact:local}" --format '{{.Id}}' ;;
  *) printf '%s\n' 'CAMACT_VERIFY_SKIP_BUILD must be 0 or 1' >&2; exit 2 ;;
esac
docker compose --profile tools run --rm -T storage-init
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
