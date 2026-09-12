#!/usr/bin/env bash
set -euo pipefail

REPO="huhengbo/DnsForward"
BINARY="/usr/local/bin/dnsforward"
CONTROL="/usr/local/bin/dnsforwardctl"
CONFIG_DIR="/etc/dnsforward"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
UNIT_FILE="/etc/systemd/system/dnsforward.service"
UPDATE_SERVICE="/etc/systemd/system/dnsforward-update.service"
UPDATE_TIMER="/etc/systemd/system/dnsforward-update.timer"
RAW_SCRIPT="https://raw.githubusercontent.com/${REPO}/master/scripts/install.sh"

usage() {
  cat <<'EOF'
DnsForward Linux manager

Usage:
  dnsforwardctl install [version]
  dnsforwardctl check-update
  dnsforwardctl upgrade [version]
  dnsforwardctl auto-update enable|disable|status
  dnsforwardctl start
  dnsforwardctl stop
  dnsforwardctl restart
  dnsforwardctl status
  dnsforwardctl logs
  dnsforwardctl uninstall

Examples:
  dnsforwardctl install
  dnsforwardctl install v1.2.0
  dnsforwardctl check-update
  sudo dnsforwardctl upgrade
  sudo dnsforwardctl auto-update enable
  sudo dnsforwardctl restart
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

require_download_tools() {
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
    if [[ ! "${requested}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
      echo "Invalid version: ${requested}" >&2
      exit 1
    fi
    echo "${requested}"
    return
  fi

  local final_url
  final_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
  basename "${final_url}"
}

current_version() {
  if [[ ! -x "${BINARY}" ]]; then
    return 1
  fi
  "${BINARY}" -v 2>/dev/null | awk '{print $NF}'
}

version_is_newer() {
  local current="${1#v}"
  local latest="${2#v}"
  [[ "${current}" != "${latest}" ]] && \
    [[ "$(printf '%s\n%s\n' "${current}" "${latest}" | sort -V | tail -n1)" == "${latest}" ]]
}

download_release() {
  local version="$1"
  local arch="$2"
  local target_dir="$3"
  local archive="dnsforward_${version}_linux_${arch}.tar.gz"
  local base_url="https://github.com/${REPO}/releases/download/${version}"

  curl -fL "${base_url}/${archive}" -o "${target_dir}/${archive}"
  curl -fL "${base_url}/checksums.txt" -o "${target_dir}/checksums.txt"

  (
    cd "${target_dir}"
    grep -F "  ${archive}" checksums.txt | sha256sum -c -
    tar -xzf "${archive}"
  )

  if [[ ! -x "${target_dir}/dnsforward" ]]; then
    echo "Release archive does not contain dnsforward." >&2
    exit 1
  fi

  local packaged_version
  packaged_version="$("${target_dir}/dnsforward" -v | awk '{print $NF}')"
  if [[ "${packaged_version}" != "${version}" ]]; then
    echo "Release binary version mismatch: expected ${version}, got ${packaged_version}" >&2
    exit 1
  fi
}

install_service() {
  require_root
  require_linux_systemd
  require_download_tools

  local arch version tmpdir
  arch="$(resolve_arch)"
  version="$(resolve_version "${1:-latest}")"
  tmpdir="$(mktemp -d)"
  trap "rm -rf '${tmpdir}'" EXIT

  echo "Installing DnsForward ${version} (${arch})..."
  download_release "${version}" "${arch}" "${tmpdir}"

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
  echo "Manage: dnsforwardctl {check-update|upgrade|auto-update|start|stop|restart|status|logs|uninstall}"
}

check_update() {
  require_download_tools

  local current latest
  current="$(current_version || true)"
  if [[ -z "${current}" ]]; then
    echo "DnsForward is not installed at ${BINARY}." >&2
    exit 1
  fi
  latest="$(resolve_version latest)"

  echo "Current: ${current}"
  echo "Latest:  ${latest}"
  if [[ "${current}" == "${latest}" ]]; then
    echo "DnsForward is up to date."
    return 0
  fi
  if version_is_newer "${current}" "${latest}"; then
    echo "Update available: ${current} -> ${latest}"
    return 2
  fi
  echo "Installed version is newer than the latest public release."
}

upgrade_service() {
  require_root
  require_linux_systemd
  require_download_tools

  if [[ ! -x "${BINARY}" ]]; then
    echo "DnsForward is not installed. Run: dnsforwardctl install" >&2
    exit 1
  fi

  local current arch version tmpdir backup
  current="$(current_version)"
  arch="$(resolve_arch)"
  version="$(resolve_version "${1:-latest}")"

  if [[ "${current}" == "${version}" ]]; then
    echo "DnsForward ${current} is already installed."
    return 0
  fi

  tmpdir="$(mktemp -d)"
  backup="$(mktemp /tmp/dnsforward-backup.XXXXXX)"
  trap "rm -rf '${tmpdir}' '${backup}'" EXIT

  echo "Upgrading DnsForward ${current} -> ${version} (${arch})..."
  download_release "${version}" "${arch}" "${tmpdir}"
  cp -p "${BINARY}" "${backup}"

  install -m 0755 "${tmpdir}/dnsforward" "${BINARY}"
  curl -fsSL "${RAW_SCRIPT}" -o "${tmpdir}/dnsforwardctl"
  install -m 0755 "${tmpdir}/dnsforwardctl" "${CONTROL}"

  if systemctl restart dnsforward && sleep 2 && systemctl is-active --quiet dnsforward; then
    echo "DnsForward upgraded successfully to ${version}."
    return 0
  fi

  echo "New version failed to start; restoring ${current}..." >&2
  install -m 0755 "${backup}" "${BINARY}"
  systemctl restart dnsforward
  if systemctl is-active --quiet dnsforward; then
    echo "Rollback completed. DnsForward ${current} is running again." >&2
  else
    echo "Rollback binary restored, but dnsforward service is still not active." >&2
  fi
  exit 1
}

write_update_units() {
  cat >"${UPDATE_SERVICE}" <<EOF
[Unit]
Description=Upgrade DnsForward to the latest stable release
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${CONTROL} upgrade
EOF

  cat >"${UPDATE_TIMER}" <<'EOF'
[Unit]
Description=Daily DnsForward update check

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF
}

auto_update() {
  require_root
  require_linux_systemd
  local action="${1:-status}"

  case "${action}" in
    enable)
      write_update_units
      systemctl daemon-reload
      systemctl enable --now dnsforward-update.timer
      echo "Automatic upgrades enabled. The timer checks daily for the latest stable release."
      ;;
    disable)
      systemctl disable --now dnsforward-update.timer 2>/dev/null || true
      rm -f "${UPDATE_TIMER}" "${UPDATE_SERVICE}"
      systemctl daemon-reload
      echo "Automatic upgrades disabled."
      ;;
    status)
      if [[ -f "${UPDATE_TIMER}" ]]; then
        systemctl status dnsforward-update.timer --no-pager
      else
        echo "Automatic upgrades are disabled."
      fi
      ;;
    *)
      echo "Usage: dnsforwardctl auto-update enable|disable|status" >&2
      exit 1
      ;;
  esac
}

uninstall_service() {
  require_root
  require_linux_systemd

  systemctl disable --now dnsforward-update.timer 2>/dev/null || true
  systemctl disable --now dnsforward 2>/dev/null || true
  rm -f "${UPDATE_TIMER}" "${UPDATE_SERVICE}" "${UNIT_FILE}" "${BINARY}" "${CONTROL}"
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
    check-update) check_update ;;
    upgrade) upgrade_service "${1:-latest}" ;;
    auto-update) auto_update "${1:-status}" ;;
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
