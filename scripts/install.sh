#!/usr/bin/env bash
set -euo pipefail

REPO="huhengbo/DnsForward"
BINARY="/usr/local/bin/dnsforward"
CONTROL="/usr/local/bin/dnsforwardctl"
CONFIG_DIR="/etc/dnsforward"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
UNIT_FILE="/etc/systemd/system/dnsforward.service"
RAW_SCRIPT="https://raw.githubusercontent.com/${REPO}/master/scripts/install.sh"

usage() {
  cat <<'EOF'
DnsForward Linux manager

Usage:
  dnsforwardctl install [version]
  dnsforwardctl start
  dnsforwardctl stop
  dnsforwardctl restart
  dnsforwardctl status
  dnsforwardctl logs
  dnsforwardctl uninstall

Examples:
  dnsforwardctl install
  dnsforwardctl install v1.1.0
  dnsforwardctl restart
EOF
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Please run as root (sudo)." >&2
    exit 1
  fi
}

require_linux_systemd() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This installer currently supports Linux only." >&2
    exit 1
  fi
  command -v systemctl >/dev/null 2>&1 || {
    echo "systemd/systemctl is required." >&2
    exit 1
  }
}

resolve_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

resolve_version() {
  local requested="${1:-latest}"
  if [[ "${requested}" != "latest" ]]; then
    echo "${requested}"
    return
  fi

  local final_url
  final_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
  basename "${final_url}"
}

install_service() {
  require_root
  require_linux_systemd
  command -v curl >/dev/null 2>&1 || {
    echo "curl is required." >&2
    exit 1
  }
  command -v sha256sum >/dev/null 2>&1 || {
    echo "sha256sum is required." >&2
    exit 1
  }
  command -v tar >/dev/null 2>&1 || {
    echo "tar is required." >&2
    exit 1
  }

  local arch version archive base_url tmpdir
  arch="$(resolve_arch)"
  version="$(resolve_version "${1:-latest}")"
  archive="dnsforward_${version}_linux_${arch}.tar.gz"
  base_url="https://github.com/${REPO}/releases/download/${version}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT

  echo "Installing DnsForward ${version} (${arch})..."
  curl -fL "${base_url}/${archive}" -o "${tmpdir}/${archive}"
  curl -fL "${base_url}/checksums.txt" -o "${tmpdir}/checksums.txt"

  (
    cd "${tmpdir}"
    grep -F "  ${archive}" checksums.txt | sha256sum -c -
    tar -xzf "${archive}"
  )

  install -m 0755 "${tmpdir}/dnsforward" "${BINARY}"
  install -d -m 0755 "${CONFIG_DIR}"
  if [[ ! -f "${CONFIG_FILE}" ]]; then
    install -m 0644 "${tmpdir}/config.example.yaml" "${CONFIG_FILE}"
  else
    echo "Keeping existing config: ${CONFIG_FILE}"
  fi

  curl -fsSL "${RAW_SCRIPT}" -o "${CONTROL}"
  chmod 0755 "${CONTROL}"

  cat >"${UNIT_FILE}" <<EOF
[Unit]
Description=DnsForward DNS service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BINARY} -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now dnsforward

  echo
  echo "DnsForward ${version} installed."
  echo "Config: ${CONFIG_FILE}"
  echo "Manage: dnsforwardctl {start|stop|restart|status|logs|uninstall}"
}

uninstall_service() {
  require_root
  require_linux_systemd

  systemctl disable --now dnsforward 2>/dev/null || true
  rm -f "${UNIT_FILE}" "${BINARY}" "${CONTROL}"
  systemctl daemon-reload

  echo "DnsForward service and binaries removed."
  if [[ -f "${CONFIG_FILE}" ]]; then
    echo "Config kept at ${CONFIG_FILE}"
  fi
}

service_action() {
  require_root
  require_linux_systemd
  systemctl "$1" dnsforward
}

show_logs() {
  require_root
  require_linux_systemd
  journalctl -u dnsforward -f
}

main() {
  local command="${1:-install}"
  shift || true

  case "${command}" in
    install) install_service "${1:-latest}" ;;
    start) service_action start ;;
    stop) service_action stop ;;
    restart) service_action restart ;;
    status) service_action status ;;
    logs) show_logs ;;
    uninstall) uninstall_service ;;
    -h|--help|help) usage ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
