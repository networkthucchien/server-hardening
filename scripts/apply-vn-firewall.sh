#!/usr/bin/env bash
# Áp dụng rule iptables/ip6tables lọc GeoIP Việt Nam.
# Hỗ trợ 2 chế độ cấu hình trong /etc/vn-firewall/config.env:
#   - GEOIP_MODE="ssh" : Chỉ chặn IP ngoài Việt Nam vào SSH (mặc định port 22). Mọi dịch vụ khác allow all.
#   - GEOIP_MODE="all" : Chặn IP ngoài Việt Nam cho TẤT CẢ dịch vụ (có thể mở ngoại lệ qua PUBLIC_TCP_PORTS / PUBLIC_UDP_PORTS).
# Sử dụng cơ chế -j RETURN cho lưu lượng hợp lệ để tương thích hoàn toàn với Fail2ban, UFW và Docker.
set -euo pipefail

CONFIG_DIR="/etc/vn-firewall"
CONFIG_FILE="${CONFIG_DIR}/config.env"
IPSET_SAVE_FILE="${CONFIG_DIR}/ipset.rules"

# Giá trị mặc định (có thể ghi đè trong /etc/vn-firewall/config.env)
GEOIP_MODE="all"
SSH_PORT="22"
PUBLIC_TCP_PORTS=""
PUBLIC_UDP_PORTS=""

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
fi

VN_V4_SET="vn_allow_v4"
VN_V6_SET="vn_allow_v6"
ADMIN_V4_SET="admin_whitelist_v4"
ADMIN_V6_SET="admin_whitelist_v6"

CHAIN_INPUT="VN_GEOIP_INPUT"
CHAIN_DOCKER="VN_GEOIP_DOCKER"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Khôi phục ipset từ snapshot nếu chưa tồn tại trong kernel (ví dụ sau reboot)
if ! ipset list "$VN_V4_SET" >/dev/null 2>&1; then
    if [[ -s "$IPSET_SAVE_FILE" ]]; then
        log "Khôi phục ipset từ $IPSET_SAVE_FILE..."
        ipset restore -exist < "$IPSET_SAVE_FILE"
    else
        log "LỖI: Không tìm thấy ipset '$VN_V4_SET' và file $IPSET_SAVE_FILE. Hãy chạy update-vn-ipset.sh trước!"
        exit 1
    fi
fi

# Kiểm tra ipset VN không bị rỗng trước khi áp rule DROP
v4_entries="$(ipset list "$VN_V4_SET" | awk '/^Number of entries:/ {print $4}')"
if [[ -z "$v4_entries" || "$v4_entries" -lt 200 ]]; then
    log "LỖI: ipset '$VN_V4_SET' chỉ có '${v4_entries:-0}' mục. Dừng áp dụng firewall để tránh khóa server!"
    exit 1
fi

remove_jumps() {
    local cmd="$1"      # iptables hoặc ip6tables
    local parent="$2"   # INPUT hoặc DOCKER-USER
    local target="$3"   # VN_GEOIP_INPUT hoặc VN_GEOIP_DOCKER

    # Xóa mọi jump rule tới target (cả dạng toàn bộ lẫn dạng theo --dport)
    while "$cmd" -S "$parent" 2>/dev/null | grep -q -- "-j ${target}\b"; do
        local rule_spec
        rule_spec="$("$cmd" -S "$parent" | grep -m1 -- "-j ${target}\b" | sed "s/^-A ${parent} //")"
        # shellcheck disable=SC2086
        "$cmd" -D "$parent" $rule_spec
    done
}

apply_ipv4() {
    # --- 1. Host INPUT chain ---
    iptables -N "$CHAIN_INPUT" 2>/dev/null || true
    iptables -F "$CHAIN_INPUT"

    # Cho phép loopback & các kết nối đã thiết lập (giữ SSH hiện tại + outbound apt/curl/DNS)
    iptables -A "$CHAIN_INPUT" -i lo -j RETURN
    iptables -A "$CHAIN_INPUT" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

    # Cho phép mạng nội bộ / container / VPN nội bộ (RFC1918 + CGNAT)
    iptables -A "$CHAIN_INPUT" -s 10.0.0.0/8 -j RETURN
    iptables -A "$CHAIN_INPUT" -s 172.16.0.0/12 -j RETURN
    iptables -A "$CHAIN_INPUT" -s 192.168.0.0/16 -j RETURN
    iptables -A "$CHAIN_INPUT" -s 100.64.0.0/10 -j RETURN

    # Nếu chế độ "all" nhưng có mở ngoại lệ một số port công khai (vd: 80,443)
    if [[ "$GEOIP_MODE" == "all" && -n "$PUBLIC_TCP_PORTS" ]]; then
        iptables -A "$CHAIN_INPUT" -p tcp -m multiport --dports "$PUBLIC_TCP_PORTS" -j RETURN
    fi
    if [[ "$GEOIP_MODE" == "all" && -n "$PUBLIC_UDP_PORTS" ]]; then
        iptables -A "$CHAIN_INPUT" -p udp -m multiport --dports "$PUBLIC_UDP_PORTS" -j RETURN
    fi

    # Cho phép Admin whitelist & IP Việt Nam -> RETURN để Fail2ban/UFW xử lý tiếp
    iptables -A "$CHAIN_INPUT" -m set --match-set "$ADMIN_V4_SET" src -j RETURN
    iptables -A "$CHAIN_INPUT" -m set --match-set "$VN_V4_SET" src -j RETURN

    # Chặn toàn bộ IP ngoài Việt Nam
    iptables -A "$CHAIN_INPUT" -j DROP

    # Gắn jump rule vào đầu INPUT theo GEOIP_MODE
    remove_jumps iptables INPUT "$CHAIN_INPUT"
    if [[ "$GEOIP_MODE" == "ssh" ]]; then
        iptables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j "$CHAIN_INPUT"
        log "Đã áp dụng rule IPv4 trên INPUT: CHỈ lọc SSH port ${SSH_PORT} (các dịch vụ khác allow all)."
    else
        iptables -I INPUT 1 -j "$CHAIN_INPUT"
        log "Đã áp dụng rule IPv4 trên INPUT: lọc TẤT CẢ dịch vụ (VN prefixes: $v4_entries, public TCP: '${PUBLIC_TCP_PORTS:-none}')."
    fi

    # --- 2. Docker / Containerlab DOCKER-USER chain ---
    if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
        remove_jumps iptables DOCKER-USER "$CHAIN_DOCKER"
        if [[ "$GEOIP_MODE" == "all" ]]; then
            iptables -N "$CHAIN_DOCKER" 2>/dev/null || true
            iptables -F "$CHAIN_DOCKER"

            iptables -A "$CHAIN_DOCKER" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
            iptables -A "$CHAIN_DOCKER" -s 127.0.0.0/8 -j RETURN
            iptables -A "$CHAIN_DOCKER" -s 10.0.0.0/8 -j RETURN
            iptables -A "$CHAIN_DOCKER" -s 172.16.0.0/12 -j RETURN
            iptables -A "$CHAIN_DOCKER" -s 192.168.0.0/16 -j RETURN
            iptables -A "$CHAIN_DOCKER" -s 100.64.0.0/10 -j RETURN
            if [[ -n "$PUBLIC_TCP_PORTS" ]]; then
                iptables -A "$CHAIN_DOCKER" -p tcp -m multiport --dports "$PUBLIC_TCP_PORTS" -j RETURN
            fi
            if [[ -n "$PUBLIC_UDP_PORTS" ]]; then
                iptables -A "$CHAIN_DOCKER" -p udp -m multiport --dports "$PUBLIC_UDP_PORTS" -j RETURN
            fi
            iptables -A "$CHAIN_DOCKER" -m set --match-set "$ADMIN_V4_SET" src -j RETURN
            iptables -A "$CHAIN_DOCKER" -m set --match-set "$VN_V4_SET" src -j RETURN
            iptables -A "$CHAIN_DOCKER" -j DROP

            iptables -I DOCKER-USER 1 -j "$CHAIN_DOCKER"
            log "Đã áp dụng rule IPv4 trên DOCKER-USER (bảo vệ cả port container publish)."
        else
            iptables -F "$CHAIN_DOCKER" 2>/dev/null || true
            iptables -X "$CHAIN_DOCKER" 2>/dev/null || true
            log "Chế độ 'ssh': Không áp dụng GeoIP lên DOCKER-USER (dịch vụ container allow all)."
        fi
    fi
}

apply_ipv6() {
    if ! command -v ip6tables >/dev/null 2>&1; then
        return 0
    fi
    if ! ipset list "$VN_V6_SET" >/dev/null 2>&1; then
        return 0
    fi

    ip6tables -N "$CHAIN_INPUT" 2>/dev/null || true
    ip6tables -F "$CHAIN_INPUT"

    ip6tables -A "$CHAIN_INPUT" -i lo -j RETURN
    ip6tables -A "$CHAIN_INPUT" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    ip6tables -A "$CHAIN_INPUT" -s fe80::/10 -j RETURN
    ip6tables -A "$CHAIN_INPUT" -s fc00::/7 -j RETURN
    ip6tables -A "$CHAIN_INPUT" -p ipv6-icmp -j RETURN
    if [[ "$GEOIP_MODE" == "all" && -n "$PUBLIC_TCP_PORTS" ]]; then
        ip6tables -A "$CHAIN_INPUT" -p tcp -m multiport --dports "$PUBLIC_TCP_PORTS" -j RETURN
    fi
    if [[ "$GEOIP_MODE" == "all" && -n "$PUBLIC_UDP_PORTS" ]]; then
        ip6tables -A "$CHAIN_INPUT" -p udp -m multiport --dports "$PUBLIC_UDP_PORTS" -j RETURN
    fi
    ip6tables -A "$CHAIN_INPUT" -m set --match-set "$ADMIN_V6_SET" src -j RETURN
    ip6tables -A "$CHAIN_INPUT" -m set --match-set "$VN_V6_SET" src -j RETURN
    ip6tables -A "$CHAIN_INPUT" -j DROP

    remove_jumps ip6tables INPUT "$CHAIN_INPUT"
    if [[ "$GEOIP_MODE" == "ssh" ]]; then
        ip6tables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j "$CHAIN_INPUT"
        log "Đã áp dụng rule IPv6 trên INPUT: CHỈ lọc SSH port ${SSH_PORT}."
    else
        ip6tables -I INPUT 1 -j "$CHAIN_INPUT"
        log "Đã áp dụng rule IPv6 trên INPUT: lọc TẤT CẢ dịch vụ."
    fi
}

apply_ipv4
apply_ipv6
