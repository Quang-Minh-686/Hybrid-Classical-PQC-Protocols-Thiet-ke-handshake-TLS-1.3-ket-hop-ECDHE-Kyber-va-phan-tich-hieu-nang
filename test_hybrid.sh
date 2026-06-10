#!/usr/bin/env bash
# test_hybrid.sh
# Kiểm tra nhanh hybrid TLS 1.3 handshake (ECDHE + ML-KEM)
#
# Cách dùng:
#   chmod +x test_hybrid.sh
#   ./test_hybrid.sh
#
# Yêu cầu:
#   - OpenSSL 4.0 build tại OPENSSL_DIR
#   - oqs-provider đã build
#   - cert + key tự ký (script tự tạo nếu chưa có)

set -euo pipefail

# ------------------------------------------------------------------ #
# CẤU HÌNH — chỉnh lại cho khớp môi trường của bạn                   #
# ------------------------------------------------------------------ #
OPENSSL_DIR="/mnt/d/hybrid-tls/deps/openssl"
OQS_PROVIDER="/mnt/d/hybrid-tls/deps/openssl/lib64/ossl-modules/oqsprovider.so"
CERT_DIR="$(dirname "$0")/certs"
PORT=14433
SERVER_LOG="/tmp/hybrid_server.log"
CLIENT_LOG="/tmp/hybrid_client.log"

OPENSSL="$OPENSSL_DIR/bin/openssl"

# Màu terminal
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ------------------------------------------------------------------ #
# 0. Kiểm tra môi trường                                              #
# ------------------------------------------------------------------ #
echo "=== Kiểm tra môi trường ==="

[[ -x "$OPENSSL" ]]         || fail "Không tìm thấy openssl tại $OPENSSL"
[[ -f "$OQS_PROVIDER" ]]    || fail "Không tìm thấy oqsprovider.so tại $OQS_PROVIDER"

# Kiểm tra oqs-provider load được không
"$OPENSSL" list -providers \
    -provider-path "$(dirname "$OQS_PROVIDER")" \
    -provider oqsprovider \
    -provider default 2>/dev/null | grep -q "oqsprovider" \
    && ok "oqs-provider load OK" \
    || fail "oqs-provider không load được — kiểm tra lại OQS_PROVIDER"

# ------------------------------------------------------------------ #
# 1. Tạo cert tự ký nếu chưa có                                      #
# ------------------------------------------------------------------ #
echo ""
echo "=== Chuẩn bị certificate ==="

mkdir -p "$CERT_DIR"

if [[ ! -f "$CERT_DIR/server.crt" ]]; then
    warn "Chưa có cert — đang tạo cert tự ký P-256..."
    "$OPENSSL" req -x509 -newkey ec \
        -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$CERT_DIR/server.key" \
        -out    "$CERT_DIR/server.crt" \
        -days 1 -nodes \
        -subj "/CN=localhost" \
        -provider default 2>/dev/null
    ok "Tạo cert xong: $CERT_DIR/server.crt"
else
    ok "Dùng cert có sẵn: $CERT_DIR/server.crt"
fi

# ------------------------------------------------------------------ #
# 2. Khởi động s_server nền                                           #
# ------------------------------------------------------------------ #
echo ""
echo "=== Khởi động s_server (port $PORT) ==="

# Dọn server cũ nếu còn chạy
pkill -f "s_server.*$PORT" 2>/dev/null || true
sleep 0.3

"$OPENSSL" s_server \
    -accept "$PORT" \
    -cert   "$CERT_DIR/server.crt" \
    -key    "$CERT_DIR/server.key" \
    -tls1_3 \
    -groups "x25519_mlkem512:x25519:P-256" \
    -provider-path "$(dirname "$OQS_PROVIDER")" \
    -provider oqsprovider \
    -provider default \
    -www \
    > "$SERVER_LOG" 2>&1 &

SERVER_PID=$!
echo "  Server PID: $SERVER_PID"
sleep 0.8   # đợi server sẵn sàng

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "s_server không khởi động được. Xem log: $SERVER_LOG"
fi
ok "s_server đang chạy"

# ------------------------------------------------------------------ #
# 3. Chạy s_client & bắt kết quả                                     #
# ------------------------------------------------------------------ #
echo ""
echo "=== Chạy s_client ==="

"$OPENSSL" s_client \
    -connect "localhost:$PORT" \
    -tls1_3 \
    -groups "x25519_mlkem512:x25519:P-256" \
    -provider-path "$(dirname "$OQS_PROVIDER")" \
    -provider oqsprovider \
    -provider default \
    -noservername \
    </dev/null \
    > "$CLIENT_LOG" 2>&1

ok "s_client kết nối xong"

# ------------------------------------------------------------------ #
# 4. Phân tích kết quả                                                #
# ------------------------------------------------------------------ #
echo ""
echo "=== Kết quả handshake ==="

# Lấy TLS version
TLS_VER=$(grep "Protocol  :" "$CLIENT_LOG" | awk '{print $NF}')
echo "  TLS version  : ${TLS_VER:-<không tìm thấy>}"

# Lấy cipher suite
CIPHER=$(grep "Cipher    :" "$CLIENT_LOG" | awk '{print $NF}')
echo "  Cipher suite : ${CIPHER:-<không tìm thấy>}"

# Lấy group đã negotiate — đây là chỉ số quan trọng nhất
GROUP=$(grep -E "Server Temp Key|group:" "$CLIENT_LOG" | head -1)
echo "  Negotiated   : ${GROUP:-<không tìm thấy>}"

# Kiểm tra có phải hybrid ML-KEM không
echo ""
if echo "$GROUP $CIPHER $(cat "$CLIENT_LOG")" | grep -qi "mlkem\|kyber"; then
    echo -e "${GREEN}✅ HYBRID ML-KEM đã được negotiate thành công!${NC}"
    RESULT="PASS"
else
    echo -e "${YELLOW}⚠️  Fallback về classical (ML-KEM không được negotiate)${NC}"
    echo "   Kiểm tra oqs-provider đã load đúng chưa."
    RESULT="FALLBACK"
fi

# ------------------------------------------------------------------ #
# 5. Dọn dẹp                                                          #
# ------------------------------------------------------------------ #
echo ""
echo "=== Dọn dẹp ==="
kill "$SERVER_PID" 2>/dev/null && ok "Đã tắt s_server"

echo ""
echo "Log chi tiết:"
echo "  Server : $SERVER_LOG"
echo "  Client : $CLIENT_LOG"
echo ""

[[ "$RESULT" == "PASS" ]] && exit 0 || exit 1
