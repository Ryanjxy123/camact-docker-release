#!/usr/bin/env bash
# New Ubuntu/Debian deployment host only. Does not run during image builds.
set -euo pipefail
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  printf '%s\n' 'The verified release supports Linux x86_64.' >&2
  exit 1
fi
if [[ $EUID != 0 ]]; then
  printf '%s\n' 'Run with sudo on the dedicated deployment host.' >&2
  exit 1
fi
if command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'Docker already exists; inspect its version before changing the host.' >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
  printf '%s\n' 'This host installer requires an Ubuntu/Debian systemd host.' >&2
  exit 1
fi
apt-get update
apt-get install -y ca-certificates curl tar xz-utils iptables uidmap util-linux python3 apparmor
# Validate/load the fixed named Runner policy before installing Docker.
# Existing Docker hosts can invoke this scoped installer independently.
camact_host_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
bash "$camact_host_script_dir/install-gvisor-policy.sh" install
camact_install_tmp=$(mktemp -d -t camact-host-install-XXXXXXXX)
trap 'rm -rf -- "$camact_install_tmp"' EXIT
curl -fL --retry 3 https://download.docker.com/linux/static/stable/x86_64/docker-28.5.1.tgz -o "$camact_install_tmp/docker.tgz"
printf '%s  %s\n' 5c0d19f31fece1accd0358bb8cff591fe25d7b6cba19f0fd412cbfdc07f75ff6 "$camact_install_tmp/docker.tgz" | sha256sum -c -
tar -xzf "$camact_install_tmp/docker.tgz" -C "$camact_install_tmp"
for camact_install_binary in "$camact_install_tmp"/docker/*; do
  install -m 0755 "$camact_install_binary" /usr/local/bin/
done
install -d -m 0755 /usr/local/lib/docker/cli-plugins
curl -fL --retry 3 https://github.com/docker/compose/releases/download/v2.40.3/docker-compose-linux-x86_64 -o "$camact_install_tmp/docker-compose"
printf '%s  %s\n' dba9d98e1ba5bfe11d88c99b9bd32fc4a0624a30fafe68eea34d61a3e42fd372 "$camact_install_tmp/docker-compose" | sha256sum -c -
install -m 0755 "$camact_install_tmp/docker-compose" /usr/local/lib/docker/cli-plugins/docker-compose
curl -fL --retry 3 https://github.com/docker/buildx/releases/download/v0.29.1/buildx-v0.29.1.linux-amd64 -o "$camact_install_tmp/docker-buildx"
printf '%s  %s\n' 7d2d7d6d4680aa349614965aaa33ccec43f1a9a21e908a5ce4cb6adfa5ad5141 "$camact_install_tmp/docker-buildx" | sha256sum -c -
install -m 0755 "$camact_install_tmp/docker-buildx" /usr/local/lib/docker/cli-plugins/docker-buildx
if ! getent group docker >/dev/null; then
  groupadd --system docker
fi
cat > /etc/systemd/system/docker.service <<'UNIT'
[Unit]
Description=CamAct deployment Docker Engine
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
ExecStart=/usr/local/bin/dockerd -H unix:///var/run/docker.sock
Restart=on-failure
Delegate=yes
KillMode=process
LimitNOFILE=infinity
LimitNPROC=infinity
TasksMax=infinity
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now docker
docker version
docker compose version
docker buildx version
printf '%s\n' 'Use a dedicated account; Docker administration grants host administrator access.'
printf '%s\n' 'An administrator must grant the dedicated deployment account Docker access, then log in again.'
