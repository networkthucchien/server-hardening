#!/usr/bin/env bash
# Kiểm tra nhanh trạng thái bảo mật: SSH Hardening, GeoIP ipset/iptables, Fail2ban, Systemd Timer.
set -euo pipefail

echo "================ 1. SSH HARDENING ================"
sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|allowusers|maxauthtries|logingracetime) ' || true

echo
echo "================ 2. GEOIP IPSET =================="
for s in vn_allow_v4 vn_allow_v6 admin_whitelist_v4 admin_whitelist_v6; do
    if ipset list "$s" >/dev/null 2>&1; then
        entries="$(ipset list "$s" | awk '/^Number of entries:/ {print $4}')"
        echo "  - $s: $entries entries"
    else
        echo "  - $s: (chưa tạo)"
    fi
done

echo
echo "================ 3. FIREWALL COUNTERS ============"
if [[ -f /etc/vn-firewall/config.env ]]; then
    echo "--- Config (/etc/vn-firewall/config.env) ---"
    grep -v '^#' /etc/vn-firewall/config.env | sed '/^$/d'
fi
echo "--- IPv4 INPUT jump rule ---"
iptables -L INPUT -vn --line-numbers | grep -E 'num|VN_GEOIP_INPUT' || echo "  (Chưa kích hoạt)"
echo "--- IPv4 VN_GEOIP_INPUT ---"
iptables -L VN_GEOIP_INPUT -vn --line-numbers 2>/dev/null || echo "  (Chưa kích hoạt)"

if iptables -L VN_GEOIP_DOCKER -n >/dev/null 2>&1; then
    echo "--- IPv4 DOCKER-USER (VN_GEOIP_DOCKER) ---"
    iptables -L VN_GEOIP_DOCKER -vn --line-numbers
fi

echo
echo "================ 4. FAIL2BAN (SSHD) =============="
fail2ban-client status sshd 2>/dev/null || echo "  (Fail2ban chưa chạy hoặc chưa bật jail sshd)"

echo
echo "================ 5. AUTO-UPDATE TIMER ============"
systemctl status vn-ipset-update.timer --no-pager -l 2>/dev/null | head -n 10 || echo "  (Chưa cài timer)"
