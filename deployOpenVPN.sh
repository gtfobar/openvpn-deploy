#!/bin/bash

function installOpenVPN () {
	apt update && apt upgrade -y
	apt install openvpn easy-rsa iptables openssl  -y
	mkdir -p /etc/openvpn/easy-rsa
	cp -r /usr/share/easy-rsa /etc/openvpn/
	cd /etc/openvpn/easy-rsa || return

	# Find out if the machine uses nogroup or nobosy for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# Encryption settings
	CIPHER="AES-128-GCM"
	CERT_CURVE="prime256v1"
	CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
	DH_CURVE="prime256v1"
	HMAC_ALG="SHA256"

	echo "set_var EASYRSA_ALGO ec" > vars
	echo "set_var EASYRSA_CURVE $CERT_CURVE" >> vars

	# Generate a random, alphanumaeric identifier of 16 characters for CN and one for server name
	SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)"
	SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)"

	echo "set_var EASYRSA_REQ_CN $SERVER_CN" >> vars

	# Create the PKI, set up the CA, the DH params and the server certificate
	./easyrsa init-pki
       	./easyrsa --batch build-ca nopass

	./easyrsa build-server-full "$SERVER_NAME" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	# Generate tls-crypt key
	openvpn --genkey secret /etc/openvpn/tls-crypt.key

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/${SERVER_NAME}.crt" "pki/private/${SERVER_NAME}.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn

	# Make cert revocation list rw-r--r-- (readable for non-root)
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	PORT=$(shuf -i49152-65535 -n1) # ramdom port
	echo "port $PORT" >/etc/openvpn/server.conf
	PROTOCOL=udp
	echo "proto $PROTOCOL" >>/etc/openvpn/server.conf

	# Generate random ip range in 10.0.0.0/8 netblock to avoid collisions
	IP_RANGE="10.$(shuf -i0-255 -n1).$(shuf -i0-255 -n1).0"

	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server $IP_RANGE 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

	# Using current DNS resolvers
	RESOLVCONF='/etc/resolv.conf'
	# Obtain the resolvers from resolv.conf and use them for OpenVPN
	sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
		echo "push \"dhcp-option DNS $LINE\"" >>/etc/openvpn/server.conf
	done

	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

	# Using ECDH
	echo "dh none" >>/etc/openvpn/server.conf
	echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf

	echo "tls-crypt tls-crypt.key 0" >>/etc/openvpn/server.conf

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf

	# Create client-config-dir dir
	mkdir -p /etc/openvpn/ccd
	# Create log dir
	mkdir -p /var/log/openvpn

	# Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf

	# Apply sysctl rules
	sysctl --system


	# Don't momdify package-provided service
	cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

	if hostnamectl status | grep -qs openvz; then
		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# Another workaround to keep using /etc/openvpn/
	fi
	# Another workaround to keep using /etc/openvpn/
	sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

	systemctl daemon-reload
	systemctl enable openvpn@server
	systemctl restart openvpn@server

	# Add iptables rules
	mkdir -p /etc/iptables


	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	# $NIC can not be empty for script rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		echo
		echo "Can not detect public interface."
		echo "This needs for setup MASQUERADE."
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

	echo "#!/bin/sh
	iptables -t nat -I POSTROUTING 1 -s $IP_RANGE/24 -o $NIC -j MASQUERADE
	iptables -I INPUT 1 -i tun0 -j ACCEPT
	iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
	iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
	iptables -I INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

	echo "#!/bin/sh
	iptables -t nat -D POSTROUTING -s $IP_RANGE/24 -o $NIC -j MASQUERADE
	iptables -D INPUT -i tun0 -j ACCEPT
	iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
	iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
	iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	# Handle the rules via a systemd script
	echo "[Unit]
	Description=iptables rules for OpenVPN
	Before=network-online.target
	Wants=network-online.target

	[Service]
	Type=oneshot
	ExecStart=/etc/iptables/add-openvpn-rules.sh
	ExecStop=/etc/iptables/rm-openvpn-rules.sh
	RemainAfterExit=yes

	[Install]
	WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service
	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# client-template.txt is created so we have a template to add further users later
	echo "client" >/etc/openvpn/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/client-template.txt
	fi

	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-ouside-dns
setenv opt block-ouside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/client-template.txt
}

function newClient() {
	CLIENT_CONFIG_DIR="/etc/openvpn/server/clients"
	client=$1

	cd /etc/openvpn/easy-rsa/ || return
	./easyrsa build-client-full "$client" nopass

	[ ! -d "$CLIENT_CONFIG_DIR" ] && mkdir -p $CLIENT_CONFIG_DIR

	cp /etc/openvpn/client-template.txt "$CLIENT_CONFIG_DIR/$client.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$client.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$client.key"
		echo "</key>"

		echo "<tls-crypt>"
		cat /etc/openvpn/tls-crypt.key
		echo "</tls-crypt>"
	} >>"$CLIENT_CONFIG_DIR/$client.ovpn"

	echo ""
	echo "The configuration file has been written to $CLIENT_CONFIG_DIR/$client.ovpn."
	echo "Download the .ovpn file and import it in your OpenVPN client."
}


CLIENTS='gtfobar
sis
mom
dad
kate'

installOpenVPN


while IFS="" read -r CLIENT; do
	newClient $CLIENT
done <<< "$CLIENTS"


