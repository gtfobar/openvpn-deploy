#!/bin/bash

function installDependencies () {
	apt update && apt upgrade -y
	apt install gettext openvpn easy-rsa iptables openssl  -y
}

function setupServerPki () {
	# Create the PKI, set up the CA, the DH params and the server certificate
	# Requirements:
	# 	- easy-rsa, openvpn installed

	### Initialize and go to temporary working directory
	mkdir -p $EASYRSA_DIR
	echo "Hello"
	cp -r /usr/share/easy-rsa/* $EASYRSA_DIR || echo "Error: easy-rsa not installed"
	echo "Hello"
	pushd $EASYRSA_DIR > /dev/null || echo "Error: unable to use $EASYRSA_DIR directory"

	echo "Hello"
	./easyrsa init-pki
    ./easyrsa --batch build-ca nopass

	echo 'yes' | ./easyrsa build-server-full "$SERVER_NAME" nopass
	./easyrsa gen-crl

	# Generate tls-crypt key
	openvpn --genkey secret $OPENVPN_DIR/tls-crypt.key

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/${SERVER_NAME}.crt" "pki/private/${SERVER_NAME}.key" pki/crl.pem $OPENVPN_DIR

	# Make cert revocation list rw-r--r-- (readable for non-root)
	chmod 644 $OPENVPN_DIR/crl.pem

	popd > /dev/null || echo "Error: unable to return to previous directory"
}

function generateServerConfig () {
	# Generate server config file
	# Requirements:
	# 	- gettext installed
	# 	- server PKI initialized (setupServerPki)

	mkdir -p $OPENVPN_DIR

	# Using current DNS resolvers
	RESOLVCONF='/etc/resolv.conf'

	# Obtain first resolver from resolv.conf
	NAMESERVER=$(sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | head -n 1)

	SERVER_PORT=$SERVER_PORT \
	SERVER_NAME=$SERVER_NAME \
	PUSH_DHCP_OPTION_DNS=$PUSH_DHCP_OPTION_DNS \
	envsubst < $SERVER_TEMPLATE_FILE | removeComments > "$OPENVPN_DIR/$SERVER_NAME.conf"
}

function removeComments () {
	# Remove comments from stdin
	sed -e '/^#/d'
}

function setupClientPki () {
	# Set up client PKI.
	# Requirements:
	# 	- easy-rsa installed
	# 	- server PKI initialized
	
	# Parameters:
	local CLIENT_NAME="$1"

	pushd $EASYRSA_DIR > /dev/null || echo "Error: $EASYRSA_DIR not exists"
	echo 'yes' | ./easyrsa build-client-full "$CLIENT_NAME" nopass
	popd
}

function generateClientConfig () {
	# Generate client config file
	# Requirements:
	# 	- gettext installed
	# 	- server PKI initialized (setupServerPki)
	# 	- client PKI initialized (setupClientPki)

	# Parameters:
	local CLIENT_NAME="$1"


	local CLIENT_CONFIG_FILE="$CLIENT_CONFIG_DIR/$CLIENT_NAME.ovpn"
	mkdir -p $OPENVPN_DIR

	SERVER_IP=$SERVER_IP \
	SERVER_PORT=$SERVER_PORT \
	SERVER_NAME=$SERVER_NAME \
	# CA_CRT="$(cat $OPENVPN_DIR/ca.crt)" \
	# CLIENT_CRT="$(cat $EASYRSA_DIR/pki/issued/$CLIENT_NAME.crt)" \
	# CLIENT_KEY="$(cat $EASYRSA_DIR/pki/private/$CLIENT_NAME.key)" \
	# TLS_CRYPT_KEY="$(cat $OPENVPN_DIR/tls-crypt.key)" \
	envsubst < $CLIENT_TEMPLATE_FILE | removeComments > "$CLIENT_CONFIG_FILE"
	cat $EASYRSA_DIR/pki/inline/$CLIENT_NAME.inline >> "$CLIENT_CONFIG_FILE"
	
	{
		echo "<tls-crypt>"
		cat $OPENVPN_DIR/tls-crypt.key | removeComments
		echo "</tls-crypt>" 
	} >> "$CLIENT_CONFIG_FILE"
}

function addClient () {
	# Add a client
	# Requirements:
	# 	- gettext installed
	# 	- server PKI initialized (setupServerPki)

	# Parameters:
	local CLIENT_NAME="$1"

	mkdir -p $CLIENT_CONFIG_DIR

	setupClientPki $CLIENT_NAME
	generateClientConfig $CLIENT_NAME
}

function addClientsFromList () {
	# Generate client config files

	for client in $(cat $CLIENT_LIST_FILE); do
		addClient $client
	done
}

function configureIpTables () {
	# Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	sysctl --system

	mkdir -p $IPTABLES_DIR

	NIC=$NETWORK_INTERFACE \
	IP_RANGE=$IP_RANGE \
	PORT=$SERVER_PORT \
	PROTOCOL=udp \
	envsubst < $ADD_OPENVPN_RULES_TEMPLATE_FILE > $IPTABLES_DIR/add-openvpn-rules.sh

	NIC=$NETWORK_INTERFACE \
	IP_RANGE=$IP_RANGE \
	PORT=$SERVER_PORT \
	PROTOCOL=udp \
	envsubst < $REMOVE_OPENVPN_RULES_TEMPLATE_FILE > $IPTABLES_DIR/remove-openvpn-rules.sh

	chmod +x $IPTABLES_DIR/add-openvpn-rules.sh
	chmod +x $IPTABLES_DIR/remove-openvpn-rules.sh

	configureIptablesSystemd
}

function configureIptablesSystemd () {
	# Configure systemd script to enable/disable iptables rules for OpenVPN

	IPTABLES_DIR=$IPTABLES_DIR \
	envsubst < $IPTABLES_OPENVPN_SERVICE_TEMPLATE_FILE > /etc/systemd/system/iptables-openvpn.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn
}

### ********** Configurable parameters ********** ###

### General
# OPENVPN_DIR="/etc/openvpn"
OPENVPN_DIR="/tmp/openvpn"
EASYRSA_DIR="$OPENVPN_DIR/easy-rsa"
IPTABLES_DIR="/etc/iptables"
NETWORK_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

### Server
SERVER_NAME=$server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)
SERVER_PORT=$(shuf -i49152-65535 -n1)
IP_RANGE="10.$(shuf -i0-255 -n1).$(shuf -i0-255 -n1).0"

# Requires external interaction, but works fine with multiple network interfaces
# SERVER_IP=${"$(curl -s ifconfig.me)"}

# May not work properly with multiple network interfaces
SERVER_IP="$(hostname -I | awk '{print $1}')"

### Clients
CLIENT_LIST_FILE="$(realpath client-list.txt)"
CLIENT_CONFIG_DIR="${OPENVPN_DIR}/ccd"

### Template files
SERVER_TEMPLATE_FILE="$(realpath templates/server.ovpn.template)"
CLIENT_TEMPLATE_FILE="$(realpath templates/client.ovpn.template)"
ADD_OPENVPN_RULES_TEMPLATE_FILE="$(realpath templates/add-openvpn-rules.sh.template)"
REMOVE_OPENVPN_RULES_TEMPLATE_FILE="$(realpath templates/remove-openvpn-rules.sh.template)"
IPTABLES_OPENVPN_SERVICE_TEMPLATE_FILE="$(realpath templates/iptables-openvpn.service.template)"

# Easy-rsa
EASYRSA_ALGO=ec
EASYRSA_CURVE=prime256v1
EASYRSA_REQ_CN=$SERVER_NAME
EASYRSA_CRL_DAYS=3650

### ********** Main ********** ###

COMMAND=$1
if [[ $COMMAND == "install-deps" ]]; then
	installDependencies
elif [[ $COMMAND == "remove-deps" ]]; then
	#todo
	# removeDependencies
	echo "Not implemented"
elif [[ $COMMAND == "setup-server" ]]; then
	SERVER_NAME=${2:-$SERVER_NAME}
	setupServerPki
	generateServerConfig
elif [[ $COMMAND == "add-client" ]]; then
	CLIENT_NAME=${2:-$CLIENT_NAME}
	addClient $CLIENT_NAME
elif [[ $COMMAND == "add-clients" ]]; then
	CLIENT_LIST_FILE=${2:-$CLIENT_LIST_FILE}
	addClientsFromList
elif [[ $COMMAND == "remove-iptables" ]]; then
	#todo
	# removeIpTables
	echo "Not implemented"
elif [[ $COMMAND == "configure-iptables" ]]; then
	configureIpTables
elif [[ $COMMAND == "revoke-client" ]]; then
	#todo
	CLIENT_NAME=${2:-$CLIENT_NAME}
	# revokeClient $CLIENT_NAME
	# echo "Not implemented"
else
	echo "Usage: $0 [install-deps|setup-server|add-client|add-clients|configure-iptables]"
fi
