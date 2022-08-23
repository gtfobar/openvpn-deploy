# Get OpenVPN port from the configuration
PORT=$(grep ^port  /etc/openvpn/server.conf | cut -d " " -f 2)
PROTOCOL=$(grep ^proto  /etc/openvpn/server.conf | cut -d " " -f 2)

# Stop OpenVPN
systemctl disable openvpn@server
systemctl stop openvpn@server
# Remove customised service
rm /etc/systemd/system/openvpn\@.service

# Remove the iptables rules related to the script
systemctl stop iptables-openvpn
# Cleanup
systemctl disable iptables-openvpn
rm /etc/systemd/system/iptables-openvpn.service
systemctl daemon-reload
rm /etc/iptables/add-openvpn-rules.sh
rm /etc/iptables/rm-openvpn-rules.sh

# SELinux
if hash sestatus 2>/dev/null; then
	if sestatus | grep "Current mode" | grep -qs "enforcing"; then
		if [[ $PORT != 1194 ]]; then
			semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
		fi
	fi
fi

apt-get remove --purge -y openvpn
if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
	rm /etc/apt/sources.list.d/openvpn.list
	apt-get update
fi

# Cleanup
find /home/ -maxdepth 2 -name "*.ovpn" -delete
find /root/ -maxdepth 1 -name "*.ovpn" -delete
rm -rf /etc/openvpn
rm -rf /usr/share/doc/openvpn*
rm -f /etc/sysctl.d/99-openvpn.conf
rm -rf /var/log/openvpn

# Unbound
if [[ -e /etc/unbound/openvpn.conf ]]; then
	removeUnbound
fi
echo ""
echo "OpenVPN removed!"
