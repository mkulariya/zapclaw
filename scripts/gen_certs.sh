#!/usr/bin/env bash
# Pincer mTLS Certificate Generator
# Generates self-signed certificates for outbound/inbound tunnel mTLS.
#
# Usage: ./scripts/gen_certs.sh [output_dir]
# Default output: ./certs/

set -euo pipefail

OUTPUT_DIR="${1:-./certs}"
DAYS=365
KEY_SIZE=4096
CN_CA="Pincer CA"
CN_SERVER="pincer-server"
CN_CLIENT="pincer-client"

echo "🔐 Pincer Certificate Generator"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Output:  $OUTPUT_DIR"
echo "  Validity: $DAYS days"
echo "  Key size: $KEY_SIZE bits"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

# --- 1. Generate CA certificate ---
echo "📜 Generating CA certificate..."
openssl genrsa -out "$OUTPUT_DIR/ca-key.pem" "$KEY_SIZE" 2>/dev/null
openssl req -new -x509 \
    -key "$OUTPUT_DIR/ca-key.pem" \
    -out "$OUTPUT_DIR/ca-cert.pem" \
    -days "$DAYS" \
    -subj "/CN=$CN_CA/O=Pincer/OU=Security" \
    2>/dev/null

# --- 2. Generate server certificate ---
echo "🖥️  Generating server certificate..."
openssl genrsa -out "$OUTPUT_DIR/server-key.pem" "$KEY_SIZE" 2>/dev/null
openssl req -new \
    -key "$OUTPUT_DIR/server-key.pem" \
    -out "$OUTPUT_DIR/server.csr" \
    -subj "/CN=$CN_SERVER/O=Pincer/OU=Server" \
    2>/dev/null

# Server extensions (SAN for localhost)
cat > "$OUTPUT_DIR/server-ext.cnf" << EOF
[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = pincer
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl x509 -req \
    -in "$OUTPUT_DIR/server.csr" \
    -CA "$OUTPUT_DIR/ca-cert.pem" \
    -CAkey "$OUTPUT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/server-cert.pem" \
    -days "$DAYS" \
    -extensions v3_req \
    -extfile "$OUTPUT_DIR/server-ext.cnf" \
    2>/dev/null

# --- 3. Generate client certificate ---
echo "👤 Generating client certificate..."
openssl genrsa -out "$OUTPUT_DIR/client-key.pem" "$KEY_SIZE" 2>/dev/null
openssl req -new \
    -key "$OUTPUT_DIR/client-key.pem" \
    -out "$OUTPUT_DIR/client.csr" \
    -subj "/CN=$CN_CLIENT/O=Pincer/OU=Client" \
    2>/dev/null

openssl x509 -req \
    -in "$OUTPUT_DIR/client.csr" \
    -CA "$OUTPUT_DIR/ca-cert.pem" \
    -CAkey "$OUTPUT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/client-cert.pem" \
    -days "$DAYS" \
    2>/dev/null

# --- 4. Clean up CSR files ---
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/*.cnf "$OUTPUT_DIR"/*.srl

# --- 5. Set restrictive permissions ---
chmod 600 "$OUTPUT_DIR"/*-key.pem
chmod 644 "$OUTPUT_DIR"/*-cert.pem
chmod 644 "$OUTPUT_DIR"/ca-cert.pem

echo ""
echo "✅ Certificates generated successfully!"
echo ""
echo "  Files created:"
echo "  ├── ca-cert.pem       (CA certificate)"
echo "  ├── ca-key.pem        (CA private key) ⚠️  KEEP SECURE"
echo "  ├── server-cert.pem   (Server certificate)"
echo "  ├── server-key.pem    (Server private key) ⚠️  KEEP SECURE"
echo "  ├── client-cert.pem   (Client certificate)"
echo "  └── client-key.pem    (Client private key) ⚠️  KEEP SECURE"
echo ""
echo "  Usage:"
echo "    pincer --client-cert $OUTPUT_DIR/client-cert.pem \\"
echo "              --client-key  $OUTPUT_DIR/client-key.pem \\"
echo "              --ca-cert     $OUTPUT_DIR/ca-cert.pem"
echo ""
