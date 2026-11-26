#!/usr/bin/env bash
# Gỡ bỏ khẩn cấp toàn bộ rule GeoIP (khôi phục truy cập từ mọi quốc gia).
set -euo pipefail

CHAIN_INPUT="VN_GEOIP_INPUT"
CHAIN_DOCKER="VN_GEOIP_DOCKER"

remove_jumps() {
    local cmd="$1"
    local parent="$2"
    local target="$3"
    while "$cmd" -S "$parent" 2>/dev/null | grep -q -- "-j ${target}\b"; do
        local rule_spec
        rule_spec="$("$cmd" -S "$parent" | grep -m1 -- "-j ${target}\b" | sed "s/^-A ${parent} //")"
        # shellcheck disable=SC2086
        "$cmd" -D "$parent" $rule_spec
    done
}

echo "[*] Đang gỡ bỏ rule GeoIP trên iptables/ip6tables..."

remove_jumps iptables INPUT "$CHAIN_INPUT"
iptables -F "$CHAIN_INPUT" 2>/dev/null || true
iptables -X "$CHAIN_INPUT" 2>/dev/null || true

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    remove_jumps iptables DOCKER-USER "$CHAIN_DOCKER"
    iptables -F "$CHAIN_DOCKER" 2>/dev/null || true
    iptables -X "$CHAIN_DOCKER" 2>/dev/null || true
fi

if command -v ip6tables >/dev/null 2>&1; then
    remove_jumps ip6tables INPUT "$CHAIN_INPUT"
    ip6tables -F "$CHAIN_INPUT" 2>/dev/null || true
    ip6tables -X "$CHAIN_INPUT" 2>/dev/null || true
fi

echo "[+] Đã gỡ bỏ hoàn toàn rule GeoIP."
