#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "REQUIRES SUDO PRIVILEGES"
    exit 1
fi
echo -e "\033[0;32m# CONFIGURING BIND9:\033[0m"
apt install bind9 bind9utils bind9-doc
curl -o /usr/share/dns/root.hints https://www.internic.net/domain/named.root
cat <<EOL > /etc/default/named
RESOLVCONF=no
OPTIONS="-u bind -4"
EOL
systemctl restart bind9
echo -e "\033[0;32mOK\033[0m"
