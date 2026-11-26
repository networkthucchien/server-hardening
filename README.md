# Ubuntu Server Security — SSH Hardening + Vietnam GeoIP Firewall + Fail2ban

Bộ script tự động triển khai bảo mật **3 lớp** cho máy chủ Ubuntu/Debian public (hỗ trợ cả máy chủ chạy **Docker / Containerlab**):

1. **SSH Hardening**: Chặn đăng nhập `root`, tắt xác thực bằng mật khẩu, chỉ cho phép SSH Key với user được chỉ định.
2. **Vietnam GeoIP Firewall (`ipset` + `iptables`/`ip6tables`)**: Chặn kết nối mới từ IP ngoài Việt Nam ngay tại tầng kernel (hỗ trợ IPv4 & IPv6, tương thích `DOCKER-USER`, UFW và Fail2ban).
3. **Fail2ban (`sshd` aggressive)**: Tự động chặn các IP (kể cả IP trong nước) có hành vi dò mật khẩu / quét SSH, thời gian ban tăng dần theo cấp số nhân (`1h` → tối đa `7d`).

---

## Tính năng nổi bật

* **3 chế độ lọc GeoIP linh hoạt**:
  * `--mode ssh`: Chỉ chặn IP ngoài Việt Nam vào SSH (port 22); mọi dịch vụ khác (`80`, `443`, Docker, lab...) mở toàn cầu (`allow all`).
  * `--mode all`: Chặn IP ngoài Việt Nam cho **tất cả dịch vụ** (cả host lẫn port Docker publish).
  * `--mode all --public-tcp 80,443`: Chặn IP ngoài Việt Nam cho mọi dịch vụ, ngoại trừ các port công khai chỉ định.
* **An toàn chống tự khóa SSH (Anti-Lockout)**:
  * Tự kiểm tra `~/.ssh/authorized_keys` trước khi tắt `PasswordAuthentication`.
  * Tự động nhận diện IP SSH hiện tại đưa vào `/etc/vn-firewall/whitelist.txt`.
  * Bật **auto-rollback sau 120 giây** khi áp dụng firewall lần đầu — chỉ lưu vĩnh viễn khi bạn mở terminal thứ 2 kiểm tra SSH thành công và nhấn `Enter`.
* **Bền vững sau reboot & tự động cập nhật**:
  * `vn-firewall.service` tự khôi phục `ipset` từ snapshot cục bộ và nạp lại rule sau khi reboot (chạy sau `docker.service`).
  * `vn-ipset-update.timer` tự động cập nhật dải IP Việt Nam lúc `03:00` Chủ Nhật hàng tuần bằng cơ chế `ipset swap` atomic (không gián đoạn kết nối).
* **Tương thích Docker**: Không restart Docker, không làm đứt kết nối `ESTABLISHED`, không ảnh hưởng container giao tiếp nội bộ hoặc gọi ra Internet.

---

## Cấu trúc thư mục

```text
scripts/
├── setup-security.sh        # Script cài đặt tổng thể (idempotent)
├── update-vn-ipset.sh       # Tải & cập nhật danh sách CIDR Việt Nam (IPv4/IPv6) vào ipset
├── apply-vn-firewall.sh     # Áp dụng rule iptables/ip6tables theo /etc/vn-firewall/config.env
├── rollback-vn-firewall.sh  # Gỡ bỏ khẩn cấp toàn bộ rule GeoIP
└── status-security.sh       # Kiểm tra nhanh trạng thái SSH, GeoIP, counters và Fail2ban
```

---

## Yêu cầu trước khi chạy

* Hệ điều hành: Ubuntu 20.04 / 22.04 / 24.04 hoặc Debian tương đương.
* Đã cài đặt sẵn **SSH Public Key** trong `/home/<SSH_USER>/.ssh/authorized_keys` và đăng nhập được bằng key.
* Có quyền `sudo` / `root`.

---

## Hướng dẫn triển khai nhanh

SSH vào server mục tiêu, clone repository và chạy script theo chế độ mong muốn:

```bash
git clone https://github.com/networkthucchien/server-hardening.git
cd server-hardening/scripts
```

### Chọn 1 trong 3 chế độ triển khai

```bash
# 1. Chỉ chặn IP ngoài VN vào SSH (port 22), các dịch vụ khác (80/443/Docker...) allow all
sudo bash setup-security.sh --mode ssh

# 2. Chặn IP ngoài VN cho TẤT CẢ dịch vụ (mặc định)
sudo bash setup-security.sh --mode all

# 3. Chặn IP ngoài VN cho tất cả dịch vụ, NHƯNG mở riêng HTTP/HTTPS (80,443) toàn cầu
sudo bash setup-security.sh --mode all --public-tcp 80,443
```

> **Cấu hình một hoặc nhiều user được phép SSH** (mặc định tự nhận user hiện tại đang chạy `sudo`, hoặc giữ nguyên danh sách cũ nếu chạy lại):
> ```bash
> # Đặt danh sách user được phép SSH (ghi đè danh sách cũ):
> sudo bash setup-security.sh --mode ssh --users "ubuntu,admin,devops"
>
> # Nối thêm user mới mà GIỮ NGUYÊN toàn bộ các user đã cấu hình trước đó:
> sudo bash setup-security.sh --mode ssh --add-users "user_moi"
> ```
> *(Mỗi user đều phải tồn tại trên hệ thống và có sẵn SSH Public Key trong `~/.ssh/authorized_keys`. Danh sách chấp nhận ngăn cách bằng dấu phẩy hoặc khoảng trắng.)*

> **Cấu hình Proxy (khi server bị chặn chiều OUTPUT ra Internet)**:
> ```bash
> # Hỗ trợ HTTP, HTTPS, SOCKS5 (có hoặc không có user:pass):
> sudo bash setup-security.sh --mode ssh --proxy http://10.0.0.10:3128
> sudo bash setup-security.sh --mode ssh --proxy http://user:pass@10.0.0.10:3128
> sudo bash setup-security.sh --mode ssh --proxy socks5h://10.0.0.10:1080
> ```
> *(Cấu hình proxy được lưu tại `PROXY_URL` trong `/etc/vn-firewall/config.env` với quyền `600`, được dùng chung cho cả `apt-get`, `update-vn-ipset.sh` và lịch tự động cập nhật hàng tuần `vn-ipset-update.timer`.)*

### Xác nhận an toàn (120 giây)
Khi script áp dụng firewall và hiển thị thông báo chờ xác nhận:
1. **Giữ nguyên** cửa sổ SSH hiện tại.
2. Mở **một cửa sổ terminal mới** và thử SSH lại vào server.
3. Nếu đăng nhập thành công, quay lại cửa sổ cũ và nhấn **Enter** để xác nhận lưu vĩnh viễn. (Nếu mất kết nối, firewall sẽ tự động gỡ bỏ sau 120 giây.)

---

## Vận hành & Quản trị sau cài đặt

Tất cả script quản lý được cài sẵn vào `/usr/local/sbin/`:

| Mục đích | Lệnh |
|---|---|
| Xem trạng thái tổng quan (SSH, GeoIP, counters, Fail2ban, timer) | `sudo status-security.sh` |
| Thêm IP ngoại lệ (khi dùng VPN / đi công tác nước ngoài) | `echo "1.2.3.4" \| sudo tee -a /etc/vn-firewall/whitelist.txt && sudo update-vn-ipset.sh --whitelist-only` |
| Chuyển chế độ lọc (`ssh` ↔ `all`, sửa `PUBLIC_TCP_PORTS` hoặc `PROXY_URL`) | Sửa `/etc/vn-firewall/config.env` rồi chạy `sudo apply-vn-firewall.sh` |
| Cập nhật thủ công danh sách IP Việt Nam ngay lập tức (dùng proxy nếu đã cấu hình) | `sudo update-vn-ipset.sh` |
| Gỡ ban một IP trong Fail2ban | `sudo fail2ban-client set sshd unbanip <IP>` |
| Tắt khẩn cấp GeoIP Firewall | `sudo rollback-vn-firewall.sh` |
| Bật lại GeoIP Firewall | `sudo apply-vn-firewall.sh` |

---

## Lưu ý khi sử dụng với Docker

* Ở chế độ `--mode ssh`, firewall chỉ lọc TCP port `22` trên `INPUT`, **không can thiệp** vào `DOCKER-USER`.
* Ở chế độ `--mode all --public-tcp 80,443`, gói tin đi qua `DOCKER-USER` đã trải qua bước DNAT nên port đích là **port bên trong container**. Nếu container map khác port (ví dụ `-p 443:8443`), hãy khai báo thêm port bên trong container vào `PUBLIC_TCP_PORTS` trong `/etc/vn-firewall/config.env`.
* Khi chạy `sudo systemctl restart docker` thủ công ở chế độ `--mode all`, nên chạy lại `sudo apply-vn-firewall.sh` để đảm bảo chain `VN_GEOIP_DOCKER` luôn nằm ở đầu `DOCKER-USER`.
