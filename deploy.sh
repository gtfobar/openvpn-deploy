#!/bin/bash

function debugPrint() {
	toPrint="$1"
	newSection="${2:-false}"

	# this is the most insecure thing in the world
	if $DEBUG; then
		if $newSection; then
			echo $'\n***'
		fi
		echo $toPrint
	fi
}

function checkRoot() {
	if [ `id -u` -ne 0 ]
		then echo Please run this script as root or using sudo!
		exit
	fi
}

function installDependencies () {
	debugPrint "[*] Installing dependencies..." true
	apt update && apt upgrade -y
	for d in $DEPENDENCIES; do
		debugPrint " - $d ..."
		apt install $d -y 2>&1 > /dev/null
	done
}

function checkDependencies() {
	debugPrint "[*] Checking dependencies..." true
	for d in $DEPENDENCIES; do

		status=$(dpkg -l $d | tail -n 1 | tr -s ' ' | cut -d $' ' -f1)
		if [ "$status" == "ii" ]; then
			debugPrint " - $d installed"
			continue
		fi
		echo " - $d not installed"
		# False
		return 1
	done
	# True
	return 0
}

function serverExists() {
	if [[ -z $1 ]]; then
		echo "Please specify server name"
		exit 1
	fi
	local server_name=$1

	debugPrint "[*] Checking if server $server_name exists.."
	local server_config_dir="$OPENVPN_DIR/$server_name"
	if [ -d "$server_config_dir" ]; then
		debugPrint " - yes"
		return 0 # False
	fi
	debugPrint " - no"
	return 1
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


	echo "[*] Configuring PKI for server $server_name"

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

	debugPrint "[*] Generating server config for server $server_name" true
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
	
	debugPrint " - config for server $server_name generated under $server_config_dir/$server_name.conf:"
	if $DEBUG; then
		cat $server_config_dir/$server_name.conf
	fi
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

	debugPrint "[*] Configuring and deploying OpenVPN server systemd script..." true
	mkdir -p "/run/openvpn/$server_name"

	local systemd_script_path="/etc/systemd/system/openvpn@$server_name.service"
	# for env substitution below
	WORKING_DIR=$OPENVPN_DIR/$server_name \
	envsubst < $OPENVPN_SERVICE_TEMPLATE_FILE > $systemd_script_path
	debugPrint " - systemd script created under $systemd_script_path:"
	if $DEBUG; then
		cat $systemd_script_path
		echo
	fi

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable openvpn@$server_name
	systemctl start openvpn@$server_name
	debugPrint " - systemd script deployed"
}

function addServer() {
	# Add a server
	# Requirements:
	# 	- easy-rsa, openvpn, gettext installed (installDependencies)
	#	- superuser privileges
	# Parameters:
	# 	- server_name (optional)
	# 	- server_port (optional)
	# 	- ip_range (optional)

	### If these properties are not set, they will be randomly generated
	local server_name=${1:-"server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16)"}
	local server_port=${2:-"$(shuf -i49152-65535 -n1)"}
	local ip_range=${3:-"10.$(shuf -i0-255 -n1).$(shuf -i0-255 -n1).0"}

	if serverExists $server_name; then
		echo "Exiting..."
		# exit 1
	fi

	setupServerPki $server_name

	generateServerConfig $server_name $server_port $ip_range

	local client_config_dir="$OPENVPN_DIR/$server_name/ccd"
	mkdir -p $client_config_dir

	configureServerSystemd $server_name

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
	local client_config_dir="$server_config_dir/clients/$client_name"

	pushd "$server_config_dir/easy-rsa" > /dev/null || echo "Error: $server_config_dir/easy-rsa not exists"
	echo 'yes' | ./easyrsa build-client-full "$client_name" nopass
	debugPrint " - client PKI configured - see $server_config_dir/pki"
	mkdir -p $client_config_dir
	# cp pki/inline/$client_name.inline pki/issued/$client_name.crt pki/private/$client_name.key $server_config_dir/clients/$client_name
	cp pki/issued/$client_name.crt pki/private/$client_name.key $client_config_dir
	popd
	debugPrint " - client cert and key copied to $client_config_dir"
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

	debugPrint "[*] Generating config for client $client_name on server $server_name..." true

	# Generate inline config
	SERVER_IP=$SERVER_IP \
	SERVER_PORT=$server_port \
	SERVER_NAME=$server_name \
	CA_CRT="$(cat $OPENVPN_DIR/$server_name/ca.crt)" \
	CLIENT_CRT="$(cat $OPENVPN_DIR/$server_name/clients/$client_name/$client_name.crt)" \
	CLIENT_KEY="$(cat $OPENVPN_DIR/$server_name/clients/$client_name/$client_name.key)" \
	TLS_CRYPT_KEY="$(cat $OPENVPN_DIR/$server_name/tls-crypt.key | removeComments)" \
	envsubst < $CLIENT_INLINE_TEMPLATE_FILE | removeComments > "$client_config_inline"
	debugPrint " - inline config generated under $client_config_inline:"
	if $DEBUG; then
		cat $client_config_inline
		echo
	fi

	# Generate normal config
	SERVER_IP=$SERVER_IP \
	SERVER_PORT=$server_port \
	SERVER_NAME=$server_name \
	envsubst < $CLIENT_TEMPLATE_FILE | removeComments > "$client_config_file"
	debugPrint " - normal config generated under $client_config_file:"
	if $DEBUG; then
		cat $client_config_file
		echo
	fi
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


	if ! serverExists $server_name; then
		echo "Exiting ..."
		exit 1
	fi

	debugPrint "[*] Adding client $client_name to $server_name" true

	setupClientPki $server_name $client_name
	generateClientConfig $server_name $client_name
}

function addClientsFromList () {
	# Generate client config files

	local server_name="$1"

	for client_name in $(cat $CLIENT_LIST_FILE); do
		addClient $server_name $client_name
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

	debugPrint "[*] Configuring ip tables for $server_name... " true

	# Enable routing
	if [[ $(cat /etc/sysctl.d/99-openvpn.conf | awk '{$1=$1}1') != 'net.ipv4.ip_forward=1' ]]; then
		echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
		sysctl --system
	fi
	debugPrint " - routing enabled"

	mkdir -p $IPTABLES_DIR


	NIC=$NETWORK_INTERFACE \
	IP_RANGE=$ip_range \
	PORT=$server_port \
	PROTOCOL=udp \
	envsubst < $ADD_OPENVPN_RULES_TEMPLATE_FILE > $IPTABLES_DIR/add-rules-$server_name.sh

	debugPrint " - $IPTABLES_DIR/add-rules-$server_name.sh created:"
	if $DEBUG; then
		cat "$IPTABLES_DIR/add-rules-$server_name.sh"
		echo
	fi

	NIC=$NETWORK_INTERFACE \
	IP_RANGE=$ip_range \
	PORT=$server_port \
	PROTOCOL=udp \
	envsubst < $REMOVE_OPENVPN_RULES_TEMPLATE_FILE > $IPTABLES_DIR/remove-rules-$server_name.sh

	debugPrint " - $IPTABLES_DIR/remove-rules-$server_name.sh created:"
	if $DEBUG; then
		cat "$IPTABLES_DIR/remove-rules-$server_name.sh"
		echo
	fi

	chmod +x $IPTABLES_DIR/add-rules-$server_name.sh
	chmod +x $IPTABLES_DIR/remove-rules-$server_name.sh
	debugPrint " - permissions configured"

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

	debugPrint "[*] Deploying iptables systemd service..." true

	local iptables_service="/etc/systemd/iptables-openvpn@$server_name.service"
	envsubst < $IPTABLES_OPENVPN_SERVICE_TEMPLATE_FILE > $iptables_service
	debugPrint " - $iptables_service created:"
	if $DEBUG; then
		cat $iptables_service
		echo
	fi

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn@$server_name
	systemctl start iptables-openvpn@$server_name
	debugPrint " - iptables-openvpn@$server_name enabled and started"
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
	debugPrint "[*] Setting static ip for client $client_name on server $server_name..."
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
DEPENDENCIES="gettext openvpn easy-rsa iptables openssl"
DEBUG=true

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
CLIENT_INLINE_TEMPLATE_FILE="$(realpath templates/client-inline.ovpn.template)"

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
	checkRoot
	if ! checkDependencies; then
		installDependencies
	fi
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
	SERVER_NAME=${2}
	CLIENT_LIST_FILE=${3:-$CLIENT_LIST_FILE}
	if [[ -z $SERVER_NAME ]]; then
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
