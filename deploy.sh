#!/bin/bash

function installDependencies () {
	apt update && apt upgrade -y
	apt install gettext openvpn easy-rsa iptables openssl  -y
}

function setupServerPki () {
	# Create the PKI, set up the CA, the DH params and the server certificate
	# Requirements:
	# 	- easy-rsa, openvpn installed
	# Parameters:
	# 	- SERVER_NAME (required)

	if [[ -z $1 ]]; then
		echo "Please specify server name"
		exit 1
	fi
	local server_name=$1

	local server_config_dir="$OPENVPN_DIR/$server_name"
	### Initialize and go to temporary working directory
	mkdir -p $server_config_dir/easy-rsa
	cp -r /usr/share/easy-rsa/* $server_config_dir/easy-rsa || echo "Error: easy-rsa not installed"
	pushd $server_config_dir/easy-rsa > /dev/null || echo "Error: unable to use $server_config_dir/easy-rsa directory"
	./easyrsa init-pki
    ./easyrsa --batch build-ca nopass

	echo 'yes' | ./easyrsa build-server-full "$server_name" nopass
	./easyrsa gen-crl

	# Generate tls-crypt key
	openvpn --genkey secret $server_config_dir/tls-crypt.key

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/${server_name}.crt" "pki/private/${server_name}.key" pki/crl.pem $server_config_dir/

	# Make cert revocation list rw-r--r-- (readable for non-root)
	chmod 644 $server_config_dir/crl.pem

	popd > /dev/null || echo "Error: unable to return to previous directory"
}

function generateServerConfig () {
	# Generate server config file
	# Requirements:
	# 	- gettext installed
	# 	- server PKI initialized (setupServerPki)
	# Parameters:
	# 	- server_name (required)
	# 	- server_port (required)
	# 	- ip_range (required)

	if [[ -z $1 ]] || [[ -z $2 ]] || [[ -z $3 ]]; then
		echo "Server name, port and IP range must be specified"
		exit 1
	fi
	local server_name=$1
	local server_port=$2
	local ip_range=$3

	local server_config_dir="$OPENVPN_DIR/$server_name"

	# Using current DNS resolvers
	local resolvconf='/etc/resolv.conf'

	# Obtain first resolver from resolv.conf
	local nameserver=$(sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $resolvconf | head -n 1)

	SERVER_PORT=$server_port \
	SERVER_NAME=$server_name \
	NAMESERVER=$nameserver \
	IP_RANGE=$ip_range \
	envsubst < $SERVER_TEMPLATE_FILE | removeComments > "$server_config_dir/$server_name.conf"
}

function configureServerSystemd () {
	# Configure and deploy OpenVPN server systemd script
	# Requirements:
	# 	- dependencies installed (installDependencies)
	# 	- server PKI initialized (setupServerPki)
	# 	- server config generated (generateServerConfig)
	# Parameters:
	# 	- server_name (required)

	if [[ -z $1 ]]; then
		echo "Please specify server name"
		exit 1
	fi
	local server_name=$1

	mkdir -p "/run/openvpn/$server_name"

	OPENVPN_DIR=$OPENVPN_DIR/$server_name \
	envsubst < $OPENVPN_SERVICE_TEMPLATE_FILE > /etc/systemd/system/openvpn@$server_name.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable openvpn@$server_name
	systemctl start openvpn@$server_name
}

function addServer() {
	# Add a server
	# Requirements:
	# 	- easy-rsa, openvpn, gettext installed (installDependencies)
	# Parameters:
	# 	- server_name (optional)
	# 	- server_port (optional)
	# 	- ip_range (optional)

	### If these properties are not set, they will be randomly generated
	local server_name=${1:-"server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)"}
	local server_port=${2:-"$(shuf -i49152-65535 -n1)"}
	local ip_range=${3:-"10.$(shuf -i0-255 -n1).$(shuf -i0-255 -n1).0"}

	echo "[*] Configuring PKI for server $server_name"
	setupServerPki $server_name

	echo "[*] Generating server config for server $server_name"
	generateServerConfig $server_name $server_port $ip_range

	local client_config_dir="$OPENVPN_DIR/$server_name/ccd"
	mkdir -p $client_config_dir

	echo "[*] Configuring systemd for server $server_name"
	configureServerSystemd $server_name

	echo "[*] Configuring iptables for server $server_name"
	configureIpTables $server_name
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
	# 	- server_name (required)
	# 	- client_name (required)

	if [[ -z $1 ]] || [[ -z $2 ]]; then
		echo "Please specify client name and server name"
		exit 1
	fi
	local server_name="$1"
	local client_name="$2"

	local server_config_dir="$OPENVPN_DIR/$server_name"

	pushd "$server_config_dir/$client_name/easy-rsa" > /dev/null || echo "Error: $server_config_dir/easy-rsa not exists"
	echo 'yes' | ./easyrsa build-client-full "$client_name" nopass
	mkdir -p "$server_config_dir/clients/$client_name"
	cp pki/inline/$client_name.inline pki/issued/$client_name.crt pki/private/$client_name.key $server_config_dir/clients/$client_name
	popd
}

function generateClientConfig () {
	# Generate client config file
	# Requirements:
	# 	- gettext installed
	# 	- server PKI initialized (setupServerPki)
	# 	- client PKI initialized (setupClientPki)
	# Parameters:
	# 	- server_name (required)
	# 	- client_name (required)

	if [[ -z $1 ]] || [[ -z $2 ]]; then
		echo "Please specify client name and server name"
		exit 1
	fi
	local server_name="$1"
	local client_name="$2"

	local clients_dir="$OPENVPN_DIR/$server_name/clients/$client_name"
	mkdir -p $clients_dir

	local client_config_inline="$clients_dir/$client_name-inline.ovpn"
	local client_config_file="$clients_dir/$client_name.ovpn"

	# Rather ugly
	local server_port=$(cat $OPENVPN_DIR/$server_name/$server_name.conf | grep '^port' | awk '{print $2}')

	SERVER_IP=$SERVER_IP \
	SERVER_PORT=$server_port \
	SERVER_NAME=$server_name \
	# CA_CRT="$(cat $OPENVPN_DIR/ca.crt)" \
	# CLIENT_CRT="$(cat $EASYRSA_DIR/pki/issued/$CLIENT_NAME.crt)" \
	# CLIENT_KEY="$(cat $EASYRSA_DIR/pki/private/$CLIENT_NAME.key)" \
	# TLS_CRYPT_KEY="$(cat $OPENVPN_DIR/tls-crypt.key)" \
	envsubst < $CLIENT_TEMPLATE_FILE | removeComments > "$client_config_file"
	
	{
		cat "$client_config_file"
		echo
		cat $clients_dir/$client_name.inline
		echo
		echo "<tls-crypt>"
		cat $OPENVPN_DIR/$server_name/tls-crypt.key | removeComments
		echo "</tls-crypt>" 
	} > "$client_config_inline"
}

function addClient () {
	# Add a client
	# Requirements:
	# 	- gettext installed
	# 	- server created (addServer)
	# Parameters:
	# 	- server_name (required)
	# 	- client_name (required)

	if [[ -z $1 ]] || [[ -z $2 ]]; then
		echo "Please specify client name"
		exit 1
	fi
	local server_name="$1"
	local client_name="$2"

	setupClientPki $server_name $client_name
	generateClientConfig $server_name $client_name
}

function addClientsFromList () {
	# Generate client config files

	for client in $(cat $CLIENT_LIST_FILE); do
		addClient $client
	done
}

function configureIpTables () {
	# Create iptables rules for OpenVPN for a given ip range
	# Parameters:
	# 	- server_name (required)

	if [[ -z $1 ]]; then
		echo "Please specify IP range"
		exit 1
	fi
	local server_name=$1
	local ip_range=$(cat $OPENVPN_DIR/$server_name/$server_name.conf | grep '^server' | awk '{print $2}')
	local server_port=$(cat $OPENVPN_DIR/$server_name/$server_name.conf | grep '^port' | awk '{print $2}')

	# Enable routing
	if [[ $(/etc/sysctl.d/99-openvpn.conf) != 'net.ipv4.ip_forward=1' ]]; then
		echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
		sysctl --system
	fi

	mkdir -p $IPTABLES_DIR

	NIC=$NETWORK_INTERFACE \
	IP_RANGE=$ip_range \
	PORT=$server_port \
	PROTOCOL=udp \
	envsubst < $ADD_OPENVPN_RULES_TEMPLATE_FILE > $IPTABLES_DIR/add-rules-$server_name.sh

	NIC=$NETWORK_INTERFACE \
	IP_RANGE=$ip_range \
	PORT=$server_port \
	PROTOCOL=udp \
	envsubst < $REMOVE_OPENVPN_RULES_TEMPLATE_FILE > $IPTABLES_DIR/remove-rules-$server_name.sh

	chmod +x $IPTABLES_DIR/add-rules-$server_name.sh
	chmod +x $IPTABLES_DIR/remove-rules-$server_name.sh

	deployIptablesSystemd $server_name
}

function deployIptablesSystemd () {
	# Configure systemd script to enable/disable iptables rules for OpenVPN
	# Parameters:
	# 	- server_name (required)

	if [[ -z $1 ]]; then
		echo "Please specify IP range"
		exit 1
	fi
	local server_name=$1

	IPTABLES_DIR=$IPTABLES_DIR \
	envsubst < $IPTABLES_OPENVPN_SERVICE_TEMPLATE_FILE > /etc/systemd/system/iptables-openvpn@$server_name.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn@$server_name
	systemctl start iptables-openvpn@$server_name
}

function setStaticIp() {
	# Set static IP for a client
	# Requirements:
	# 	- server created (addServer)
	#   - client created (addClient)
	# Parameters:
	# Parameters:
	# 	- server_name (required)
	# 	- client_name (required)
	# 	- ip_address (required)

	if [[ -z $1 ]] || [[ -z $2 ]] || [[ -z $3 ]]; then
		echo "Please specify client name, server name and IP address"
		exit 1
	fi
	local server_name="$1"
	local client_name="$2"
	local ip_address="$3"

	local client_config_file="$OPENVPN_DIR/$server_name/ccd/$client_name"
	if [[ -f "$client_config_file" ]]; then
		sed -i "s/^ifconfig-push.*/ifconfig-push $ip_address/" "$client_config_file"
	else
		echo "ifconfig-push $ip_address" > "$client_config_file"
	fi
}

function unsetStaticIp() {
	# Unset static IP for a client
	# Requirements:
	# 	- server created (addServer)
	#   - client created (addClient)
	# Parameters:
	# 	- server_name (required)
	# 	- client_name (required)

	if [[ -z $1 ]] || [[ -z $2 ]]; then
		echo "Please specify client name and server name"
		exit 1
	fi
	local server_name="$1"
	local client_name="$2"

	local client_config_file="$OPENVPN_DIR/$server_name/ccd/$client_name"
	if [[ -f "$client_config_file" ]]; then
		sed -i "/^ifconfig-push.*/d" "$client_config_file"
	fi
}

### ********** Configurable parameters ********** ###

### General
OPENVPN_DIR="/etc/openvpn"
# OPENVPN_DIR="/tmp/openvpn"
# IPTABLES_DIR="/tmp/iptables"
IPTABLES_DIR="/etc/iptables"
NETWORK_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

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
OPENVPN_SERVICE_TEMPLATE_FILE="$(realpath templates/openvpn.service.template)"

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
elif [[ $COMMAND == "add-server" ]]; then
	SERVER_NAME=$2
	addServer $SERVER_NAME
elif [[ $COMMAND == "add-client" ]]; then
	SERVER_NAME=$2
	if [[ -z $2 ]]; then
		echo "Error: server name not specified"
		exit 1
	fi
	CLIENT_NAME=$3
	if [[ -z $2 ]]; then
		echo "Error: client name not specified"
		exit 1
	fi

	addClient $SERVER_NAME $CLIENT_NAME 
elif [[ $COMMAND == "add-clients" ]]; then
	CLIENT_LIST_FILE=${2:-$CLIENT_LIST_FILE}
	SERVER_NAME=${3}
	if [[ -z $3 ]]; then
		echo "Error: server name not specified"
		exit 1
	fi
	addClientsFromList $SERVER_NAME
elif [[ $COMMAND == "revoke-client" ]]; then
	#todo
	CLIENT_NAME=${2:-$CLIENT_NAME}
	# revokeClient $CLIENT_NAME
	# echo "Not implemented"
else
	echo "Usage: $0 [install-deps|setup-server|add-client|add-clients|configure-iptables|deploy-server]"
fi
