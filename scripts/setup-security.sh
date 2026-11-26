#!/usr/bin/env bash
# Script triển khai tổng thể:
#   1. Hardening SSH (chỉ cho phép user 'ubuntu' đăng nhập bằng SSH Key, tắt root & password)
#   2. GeoIP Firewall (chỉ cho phép IP Việt Nam truy cập TẤT CẢ dịch vụ + Docker ports)
#   3. Fail2ban cho SSH (chặn brute-force từ chính các IP Việt Nam, tăng dần thời gian ban)
#   4. Cơ chế tự rollback sau 120 giây nếu mất kết nối SSH khi áp dụng lần đầu
#
# Cách chạy:
#   sudo bash setup-security.sh                            (mặc định: chặn IP ngoài VN cho TẤT CẢ dịch vụ)
#   sudo bash setup-security.sh --mode ssh                 (chỉ chặn IP ngoài VN cho SSH port 22, các dịch vụ khác allow all)
#   sudo bash setup-security.sh --mode all --public-tcp 80,443  (chặn tất cả trừ port 80,443 mở toàn cầu)
#   sudo bash setup-security.sh --no-confirm               (bỏ qua bước đợi xác nhận 120s)
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Vui lòng chạy script với quyền root: sudo bash $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_USER="${SSH_USER:-ubuntu}"
GEOIP_MODE="all"
PUBLIC_TCP_PORTS=""
PUBLIC_UDP_PORTS=""
NO_CONFIRM=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            GEOIP_MODE="${2:-}"
            shift 2
            ;;
        --public-tcp)
            PUBLIC_TCP_PORTS="${2:-}"
            shift 2
            ;;
        --public-udp)
            PUBLIC_UDP_PORTS="${2:-}"
            shift 2
            ;;
        --no-confirm)
            NO_CONFIRM=true
            shift
            ;;
        *)
            echo "Tham số không hợp lệ: $1"
            exit 1
            ;;
    esac
done

if [[ "$GEOIP_MODE" != "all" && "$GEOIP_MODE" != "ssh" ]]; then
    echo "[LỖI] --mode chỉ nhận 'ssh' hoặc 'all' (hiện tại: '$GEOIP_MODE')."
    exit 1
fi

CONFIG_DIR="/etc/vn-firewall"
CONFIG_FILE="${CONFIG_DIR}/config.env"
WHITELIST_FILE="${CONFIG_DIR}/whitelist.txt"

echo "================================================================"
echo "  TRIỂN KHAI BẢO MẬT SERVER: SSH HARDENING + GEOIP VN + FAIL2BAN"
echo "================================================================"

# 0. Kiểm tra an toàn trước khi chạy
AUTH_KEYS="/home/${SSH_USER}/.ssh/authorized_keys"
if [[ ! -s "$AUTH_KEYS" ]]; then
    echo "[LỖI] Không tìm thấy SSH public key tại $AUTH_KEYS!"
    echo "      Không thể tắt PasswordAuthentication vì sẽ gây mất quyền truy cập SSH."
    exit 1
fi

# Tự động nhận diện IP hiện tại của admin để đưa vào whitelist tránh tự khóa
# (kể cả khi sudo reset biến môi trường SSH_CONNECTION/SSH_CLIENT)
CURRENT_SSH_IP=""
if [[ -n "${SSH_CONNECTION:-}" ]]; then
    CURRENT_SSH_IP="$(echo "$SSH_CONNECTION" | awk '{print $1}')"
elif [[ -n "${SSH_CLIENT:-}" ]]; then
    CURRENT_SSH_IP="$(echo "$SSH_CLIENT" | awk '{print $1}')"
else
    WHO_IP="$(who -m --ips 2>/dev/null | awk '{print $NF}' | tr -d '()' || true)"
    if [[ "$WHO_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$WHO_IP" == *:* ]]; then
        CURRENT_SSH_IP="$WHO_IP"
    fi
fi

mkdir -p "$CONFIG_DIR"
touch "$WHITELIST_FILE"
if [[ -n "$CURRENT_SSH_IP" ]]; then
    if ! grep -Fxq "$CURRENT_SSH_IP" "$WHITELIST_FILE"; then
        echo "$CURRENT_SSH_IP # Auto-added admin SSH IP on $(date '+%Y-%m-%d')" >> "$WHITELIST_FILE"
        echo "[+] Đã tự động whitelist IP hiện tại của bạn: $CURRENT_SSH_IP"
    fi
else
    echo "[!] Không phát hiện được IP từ biến SSH_CONNECTION (có thể chạy qua console)."
fi

# 1. Cài đặt các gói cần thiết
echo
echo "[1/5] Cài đặt gói ipset, iptables, curl, fail2ban..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ipset iptables curl fail2ban

# 2. Cài đặt scripts vào /usr/local/sbin
echo
echo "[2/5] Cài đặt scripts quản lý GeoIP vào /usr/local/sbin..."
install -m 755 "${SCRIPT_DIR}/update-vn-ipset.sh" /usr/local/sbin/update-vn-ipset.sh
install -m 755 "${SCRIPT_DIR}/apply-vn-firewall.sh" /usr/local/sbin/apply-vn-firewall.sh
install -m 755 "${SCRIPT_DIR}/rollback-vn-firewall.sh" /usr/local/sbin/rollback-vn-firewall.sh
install -m 755 "${SCRIPT_DIR}/status-security.sh" /usr/local/sbin/status-security.sh

# 3. SSH Hardening
echo
echo "[3/5] Cấu hình SSH Hardening (chỉ user '${SSH_USER}', chỉ dùng SSH Key)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
# Managed by setup-security.sh
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers ${SSH_USER}
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    echo "[+] Cấu hình SSH hợp lệ và đã reload thành công."
else
    echo "[LỖI] Cấu hình sshd không hợp lệ, đang xóa file 99-hardening.conf..."
    rm -f /etc/ssh/sshd_config.d/99-hardening.conf
    exit 1
fi

# 4. Cấu hình Fail2ban
echo
echo "[4/5] Cấu hình Fail2ban cho SSH..."
IGNORE_IPS="127.0.0.1/8 ::1"
[[ -n "$CURRENT_SSH_IP" ]] && IGNORE_IPS="${IGNORE_IPS} ${CURRENT_SSH_IP}"

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = ${IGNORE_IPS}
bantime = 1h
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 7d
findtime = 10m
maxretry = 3
backend = auto

[sshd]
enabled = true
port = ssh
mode = aggressive
maxretry = 3
findtime = 10m
bantime = 1h
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban
echo "[+] Fail2ban đã chạy và kích hoạt jail [sshd]."

# 5. Lưu cấu hình chế độ GeoIP + Tải danh sách IP Việt Nam + Cài đặt systemd service/timer
echo
echo "[5/5] Lưu cấu hình (GEOIP_MODE=${GEOIP_MODE}), tải danh sách IP Việt Nam và cấu hình tự khởi động..."
cat > "$CONFIG_FILE" <<EOF
# Cấu hình GeoIP Firewall (chỉnh sửa rồi chạy 'sudo apply-vn-firewall.sh' để áp dụng)
# GEOIP_MODE="ssh" -> Chỉ chặn IP ngoài VN vào SSH (port 22), các dịch vụ khác allow all
# GEOIP_MODE="all" -> Chặn IP ngoài VN cho tất cả dịch vụ (trừ PUBLIC_TCP_PORTS / PUBLIC_UDP_PORTS)
GEOIP_MODE="${GEOIP_MODE}"
SSH_PORT="22"
PUBLIC_TCP_PORTS="${PUBLIC_TCP_PORTS}"
PUBLIC_UDP_PORTS="${PUBLIC_UDP_PORTS}"
EOF

/usr/local/sbin/update-vn-ipset.sh

# Systemd service để tự nạp lại rule sau khi reboot (chạy sau docker nếu có)
cat > /etc/systemd/system/vn-firewall.service <<'EOF'
[Unit]
Description=Vietnam GeoIP Firewall (ipset + iptables)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/apply-vn-firewall.sh
ExecStop=/usr/local/sbin/rollback-vn-firewall.sh

[Install]
WantedBy=multi-user.target
EOF

# Systemd timer cập nhật danh sách IP VN định kỳ Chủ Nhật 03:00 hàng tuần
cat > /etc/systemd/system/vn-ipset-update.service <<'EOF'
[Unit]
Description=Update Vietnam GeoIP ipset lists
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/update-vn-ipset.sh
EOF

cat > /etc/systemd/system/vn-ipset-update.timer <<'EOF'
[Unit]
Description=Weekly update of Vietnam GeoIP ipset lists

[Timer]
OnCalendar=Sun *-*-* 03:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable vn-firewall.service
systemctl enable --now vn-ipset-update.timer

# Áp dụng firewall kèm dead-man's switch (tự rollback sau 120s nếu không xác nhận)
if [[ "$NO_CONFIRM" == "true" ]]; then
    /usr/local/sbin/apply-vn-firewall.sh
else
    echo
    echo "================================================================"
    echo "  CHẾ ĐỘ AN TOÀN (AUTO-ROLLBACK SAU 120 GIÂY)"
    echo "================================================================"
    echo "Đang áp dụng GeoIP Firewall..."
    /usr/local/sbin/apply-vn-firewall.sh

    (
        sleep 120
        /usr/local/sbin/rollback-vn-firewall.sh >/dev/null 2>&1 || true
        systemctl disable vn-firewall.service >/dev/null 2>&1 || true
    ) &
    ROLLBACK_PID=$!

    echo
    echo ">>> HÃY MỞ MỘT CỬA SỔ TERMINAL MỚI VÀ THỬ SSH LẠI VÀO SERVER NGAY! <<<"
    echo "    (Giữ nguyên cửa sổ này. Nếu SSH mới thành công, nhấn ENTER để xác nhận.)"
    echo "    (Nếu mất kết nối, firewall sẽ TỰ ĐỘNG GỠ BỎ sau 120 giây.)"
    echo
    if read -r -t 115 -p "Nhấn [ENTER] để xác nhận giữ cấu hình firewall: "; then
        kill "$ROLLBACK_PID" 2>/dev/null || true
        wait "$ROLLBACK_PID" 2>/dev/null || true
        echo "[+] Đã xác nhận! GeoIP Firewall được lưu vĩnh viễn."
    else
        echo
        echo "[!] Hết thời gian xác nhận — Đang chờ auto-rollback để đảm bảo an toàn..."
        wait "$ROLLBACK_PID" 2>/dev/null || true
        echo "[!] Đã rollback rule GeoIP. Hãy kiểm tra lại kết nối rồi chạy lại script."
        exit 1
    fi
fi

echo
echo "================================================================"
echo "  HOÀN TẤT! Chạy 'sudo status-security.sh' để xem trạng thái."
echo "================================================================"
/usr/local/sbin/status-security.sh
