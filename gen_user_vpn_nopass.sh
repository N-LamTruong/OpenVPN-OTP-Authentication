#!/bin/bash

#1. Kiem tra xem đa truyen ten khach hang vao hay chua??????
if [ -z "$1" ]; then
  echo "Vui long nhap ten khach hang!"
  sleep 1
  echo "Co moi viec nhap ten cung khong nho =))"
  sleep 1
  echo "Su dung: $0 <ten khach hang>"
  exit 1
fi

# Ten khach hang nhap tu tham so dong lenh
client_name="$1"
echo "Ten khach hang la: $1"
sleep 1

#2. Kiem tra xem cert cua user da ton tai hay chua????
echo "1. Check xem da ton tai user $client_name chua??"
sleep 1
if [ -f "/etc/easy-rsa/pki/reqs/$client_name.req" ]; then
  echo "Cert cho user $client_name da ton tai"
  echo "done"
  exit 1
fi
echo "User $client_name chua ton tai"
echo "done"

#3. Tao cert client va private key
echo "2. Tao cert va private key cho $client_name"
cd /etc/easy-rsa
./easyrsa build-client-full $client_name nopass
echo "done"

#4. Tao thu muc cho client va copy cert, keys vao thu muc
echo "3. Tao thu muc cho client + copy cert, keys vao thu muc"
mkdir /etc/openvpn/client/$client_name

#  Sao chep cert/key cua client vao thu muc cau hinh client OpenVPN
cp -rp /etc/easy-rsa/pki/{ca.crt,ta.key,issued/$client_name.crt,private/$client_name.key} /etc/openvpn/client/$client_name
echo "done"

#5. Tao file config client
echo "4. Tao file config client $client_name.ovpn"

tls_file="/etc/openvpn/client/$client_name/ta.key"
ca_file="/etc/openvpn/client/$client_name/ca.crt"
cert_file="/etc/openvpn/client/$client_name/$client_name.crt"
key_file="/etc/openvpn/client/$client_name/$client_name.key"

# Tao noi dung cho file .ovpn
echo "Dang tao noi dung mau"
ovpn_content=$(cat <<EOF
client
dev tun
proto udp
remote 192.168.0.119 1194
resolv-retry infinite
nobind
persist-key
persist-tun
key-direction 1
remote-cert-tls server
auth-nocache
verb 3
auth SHA512
cipher AES-256-CBC
keysize 128
mssfix
tun-mtu 1532
# use username/password authentication
auth-user-pass
# disable username/password renegotiation
reneg-sec 0
<tls-auth>
$(cat "$tls_file")
</tls-auth>
<ca>
$(cat "$ca_file")
</ca>
<cert>
$(cat "$cert_file")
</cert>
<key>
$(cat "$key_file")
</key>
EOF
)

# Duong dan thu muc dich cho file .ovpn
mkdir /root/users_vpn/$client_name

# Ghi noi dung vao file $client_name.ovpn
ovpn_file="/root/users_vpn/$client_name/$client_name.ovpn"
echo "$ovpn_content" > "$ovpn_file"

echo "Tao file $ovpn_file thanh cong!"
echo "done"

#6. Su dung Google Authenticator de tao khoa OTP cho client
echo "5. Tao OTP cho client $client_name"
echo "-1" | google-authenticator --time-based --disallow-reuse --force --rate-limit=3 --rate-time=30 --window-size=17 --issuer=VSEC --label=$client_name@openvpn --secret=/root/.$client_name.google_authenticator > /root/secret_otp/$client_name.auth

# Lay ma bi mat tu tep tin OTP
otp_secret=$(grep "Your new secret key is:" /root/secret_otp/$client_name.auth | awk '{print $6}')
echo "done"

#7. Cau hình tệp tin otp-secrets
echo "6. Cau hinh client $client_name su dung OTP"
echo "$client_name ps totp:sha1:base32:$otp_secret::xxx *" >> /etc/ppp/otp-secrets
echo "done"

#8.Convert URL to PNG
echo "7. Tao QR code"
qr_code=$(grep "https://www.google.com/chart" /root/secret_otp/$client_name.auth | awk '{print $1}')
wget --output-document=/root/users_vpn/$client_name/$client_name.png "$qr_code"
echo "Tao file $client_name.png thanh cong!"
echo "done"
