#!/usr/bin/env bash
# Cập nhật danh sách dải IP Việt Nam (IPv4 & IPv6) vào ipset theo cơ chế atomic swap (không gián đoạn).
# Hỗ trợ tải qua proxy (HTTP/HTTPS/SOCKS5) cấu hình trong /etc/vn-firewall/config.env hoặc qua --proxy.
#
# Cách chạy:
#   sudo update-vn-ipset.sh
#   sudo update-vn-ipset.sh --proxy http://10.0.0.10:3128
#   sudo update-vn-ipset.sh --whitelist-only   (chỉ cập nhật whitelist.txt, không cần Internet)
set -euo pipefail

CONFIG_DIR="/etc/vn-firewall"
CONFIG_FILE="${CONFIG_DIR}/config.env"
WHITELIST_FILE="${CONFIG_DIR}/whitelist.txt"
IPSET_SAVE_FILE="${CONFIG_DIR}/ipset.rules"

PROXY_URL="${PROXY_URL:-}"
WHITELIST_ONLY=false

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proxy)
            PROXY_URL="${2:-}"
            shift 2
            ;;
        --whitelist-only)
            WHITELIST_ONLY=true
            shift
            ;;
        *)
            echo "Tham số không hợp lệ: $1"
            exit 1
            ;;
    esac
done

VN_V4_SET="vn_allow_v4"
VN_V6_SET="vn_allow_v6"
ADMIN_V4_SET="admin_whitelist_v4"
ADMIN_V6_SET="admin_whitelist_v6"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$CONFIG_DIR"
touch "$WHITELIST_FILE"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

mask_proxy() {
    echo "$1" | sed -E 's#(://[^:/@]+:)[^@]+@#\1***@#'
}

fetch_with_fallback() {
    local out_file="$1"
    shift
    local curl_args=(-fsSL --connect-timeout 15 --max-time 60)
    if [[ -n "$PROXY_URL" ]]; then
        curl_args+=(--proxy "$PROXY_URL")
    fi

    for url in "$@"; do
        if [[ -n "$PROXY_URL" ]]; then
            log "Đang tải danh sách IP từ: $url (qua proxy $(mask_proxy "$PROXY_URL"))"
        else
            log "Đang tải danh sách IP từ: $url"
        fi
        if curl "${curl_args[@]}" "$url" -o "$out_file"; then
            if [[ -s "$out_file" ]]; then
                return 0
            fi
        fi
        log "Cảnh báo: Không tải được từ $url, thử nguồn dự phòng..."
    done
    return 1
}

update_ipset_from_file() {
    local set_name="$1"
    local family="$2"   # inet hoặc inet6
    local src_file="$3"
    local min_lines="$4"
    local tmp_set="${set_name}_tmp"

    local clean_file="${TMP_DIR}/${set_name}.clean"
    if [[ "$family" == "inet" ]]; then
        grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' "$src_file" | sort -u > "$clean_file" || true
    else
        grep -E '^[0-9a-fA-F:]+(/[0-9]{1,3})?$' "$src_file" | sort -u > "$clean_file" || true
    fi

    local count
    count="$(wc -l < "$clean_file")"
    if (( count < min_lines )); then
        log "LỖI: Danh sách $set_name chỉ có $count dòng (yêu cầu tối thiểu $min_lines). Hủy cập nhật để tránh khóa truy cập!"
        return 1
    fi

    ipset create "$set_name" hash:net family "$family" maxelem 65536 -exist
    ipset destroy "$tmp_set" 2>/dev/null || true
    ipset create "$tmp_set" hash:net family "$family" maxelem 65536

    local restore_file="${TMP_DIR}/${set_name}.restore"
    awk -v s="$tmp_set" '{print "add " s " " $1 " -exist"}' "$clean_file" > "$restore_file"
    ipset restore < "$restore_file"

    ipset swap "$tmp_set" "$set_name"
    ipset destroy "$tmp_set"
    log "Đã cập nhật ipset '$set_name': $count dải CIDR."
}

update_admin_whitelist() {
    ipset create "$ADMIN_V4_SET" hash:net family inet maxelem 1024 -exist
    ipset create "$ADMIN_V6_SET" hash:net family inet6 maxelem 1024 -exist

    local tmp_v4="${ADMIN_V4_SET}_tmp"
    local tmp_v6="${ADMIN_V6_SET}_tmp"
    ipset destroy "$tmp_v4" 2>/dev/null || true
    ipset destroy "$tmp_v6" 2>/dev/null || true
    ipset create "$tmp_v4" hash:net family inet maxelem 1024
    ipset create "$tmp_v6" hash:net family inet6 maxelem 1024

    while IFS= read -r raw_line; do
        local line
        line="$(echo "$raw_line" | sed 's/#.*//' | xargs || true)"
        [[ -z "$line" ]] && continue
        if [[ "$line" == *:* ]]; then
            ipset add "$tmp_v6" "$line" -exist
        else
            ipset add "$tmp_v4" "$line" -exist
        fi
    done < "$WHITELIST_FILE"

    ipset swap "$tmp_v4" "$ADMIN_V4_SET"
    ipset swap "$tmp_v6" "$ADMIN_V6_SET"
    ipset destroy "$tmp_v4"
    ipset destroy "$tmp_v6"
    log "Đã cập nhật whitelist quản trị từ $WHITELIST_FILE."
}

if [[ "$WHITELIST_ONLY" == "false" ]]; then
    # 1. Cập nhật IPv4 Việt Nam (bắt buộc)
    V4_RAW="${TMP_DIR}/vn_v4.zone"
    fetch_with_fallback "$V4_RAW" \
        "https://www.ipdeny.com/ipblocks/data/aggregated/vn-aggregated.zone" \
        "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr"

    update_ipset_from_file "$VN_V4_SET" "inet" "$V4_RAW" 200

    # 2. Cập nhật IPv6 Việt Nam (không làm fail toàn bộ nếu nguồn IPv6 tạm lỗi)
    V6_RAW="${TMP_DIR}/vn_v6.zone"
    if fetch_with_fallback "$V6_RAW" \
        "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/vn-aggregated.zone" \
        "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/vn.cidr"; then
        update_ipset_from_file "$VN_V6_SET" "inet6" "$V6_RAW" 20 || true
    else
        log "Cảnh báo: Không tải được danh sách IPv6 VN, giữ nguyên ipset hiện có."
        ipset create "$VN_V6_SET" hash:net family inet6 maxelem 65536 -exist
    fi
fi

# 3. Cập nhật Admin Whitelist
update_admin_whitelist

# 4. Lưu ipset ra file để khôi phục khi reboot
ipset save > "${IPSET_SAVE_FILE}.tmp"
mv "${IPSET_SAVE_FILE}.tmp" "$IPSET_SAVE_FILE"
log "Đã lưu snapshot ipset vào $IPSET_SAVE_FILE."
