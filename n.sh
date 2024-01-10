#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "REQUIRES SUDO PRIVILEGES"
    exit 1
fi
echo -e "\033[0;32m# CONFIGURING POSTFIX & DOVECOT:\033[0m"

echo -en "\e[36mCONF DOMAIN: \e[0m"
read nm_domain

regex="^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
if [[ ! $nm_domain =~ $regex ]]; then
        echo -e "\e[31mError: Cannot configure with domain \"$nm_domain\"\e[0m"
        exit 1 
fi

echo -en "\e[36mHOSTNAME: \e[0m"
read host_domain
if [[ ! $host_domain =~ $regex ]]; then
        echo -e "\e[31mError: Cannot configure with domain \"$nm_domain\"\e[0m"
        exit 1 
fi
echo -e "\e[33mPostfix configuring with domain \"$host_domain\"\e[0m"

echo -en "\e[36mTLS CERT FILE: \e[0m"
read tls_cert

echo -en "\e[36mTLS KEY FILE: \e[0m"
read tls_key


sleep 1


echo -e "\e[33mPostfix configuring with domain \"smtp.$nm_domain\"\e[0m"
sleep 1

groupadd -g 5000 shadowmail
useradd -s /usr/sbin/nologin -u 5000 -g 5000 shadowmail

usermod -aG shadowmail postfix
usermod -aG shadowmail dovecot

mkdir -p /var/mail/shadowhosts/$nm_domain
chown -R shadowmail:shadowmail /var/mail/shadowhosts
chmod -R 775 /var/mail/shadowhosts

touch /var/log/dovecot
chgrp shadowmail /var/log/dovecot
chmod 660 /var/log/dovecot


cat <<EOL > /etc/postfix/virtual_domains
$nm_domain
EOL

touch /etc/postfix/shadowmailbox

cat <<EOL > /etc/postfix/virtual_alias
root@$nm_domain admin@$nm_domain
EOL

postmap /etc/postfix/virtual_alias

cat <<EOL > /etc/postfix/main.cf
smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no

append_dot_mydomain = no

readme_directory = no

compatibility_level = 3.6

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = $host_domain
mydomain = \$myhostname
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = \$myhostname
mydestination = localhost, \$myhostname
relayhost =
mynetworks = 127.0.0.0/8
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all

virtual_mailbox_domains = /etc/postfix/virtual_domains
virtual_mailbox_base = /var/mail/shadowhosts
virtual_mailbox_maps = hash:/etc/postfix/shadowmailbox
virtual_alias_maps = hash:/etc/postfix/virtual_alias
virtual_minimum_uid = 100
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
virtual_transport = virtual
virtual_mailbox_limit = 104857600
mailbox_size_limit = 0
message_size_limit = 52428800
dovecot_destination_recipient_limit = 1

smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname
broken_sasl_auth_clients = yes

smtpd_use_tls = yes
smtpd_tls_security_level = may
smtpd_tls_auth_only = no
smtpd_tls_cert_file=$tls_cert
smtpd_tls_key_file=$tls_key
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtpd_tls_received_header = yes
smtpd_tls_security_level = may
smtp_tls_security_level = may
tls_random_source = dev:/dev/urandom

smtpd_helo_required = no
smtpd_delay_reject = yes
strict_rfc821_envelopes = yes
disable_vrfy_command = yes

anvil_rate_time_unit = 60s
smtpd_client_connection_rate_limit = 5
smtpd_client_connection_count_limit = 5
smtpd_error_sleep_time = 5s
smtpd_soft_error_limit = 2
smtpd_hard_error_limit = 3

smtpd_helo_restrictions = permit_mynetworks,
  permit_sasl_authenticated,
  reject_non_fqdn_hostname,
  reject_invalid_helo_hostname,
  reject_unknown_helo_hostname

smtpd_client_restrictions = permit_mynetworks,
  permit_sasl_authenticated,
  reject_unknown_client_hostname,
  reject_unauth_pipelining,
  reject_rbl_client zen.spamhaus.org

smtpd_sender_restrictions = reject_non_fqdn_sender,
  reject_unknown_sender_domain

smtpd_recipient_restrictions = permit_mynetworks,
  permit_sasl_authenticated,
  reject_invalid_hostname,
  reject_non_fqdn_hostname,
  reject_non_fqdn_sender,
  reject_non_fqdn_recipient,
  reject_unauth_destination,
  reject_unauth_pipelining,
  reject_rbl_client zen.spamhaus.org,
  reject_rbl_client cbl.abuseat.org,
  reject_rbl_client dul.dnsbl.sorbs.net

smtpd_recipient_limit = 250
broken_sasl_auth_clients = yes
EOL

cat <<EOL > /etc/postfix/master.cf
smtp       inet  n       -       -       -       -       smtpd
8080       inet  n       -       -       -       -       smtpd
smtps      inet  n       -       -       -       -       smtpd
submission inet  n       -       n       -       -       smtpd
pickup     fifo  n       -       -       60      1       pickup
cleanup    unix  n       -       -       -       0       cleanup
qmgr       fifo  n       -       n       300     1       qmgr
tlsmgr     unix  -       -       -       1000?   1       tlsmgr
rewrite    unix  -       -       -       -       -       trivial-rewrite
bounce     unix  -       -       -       -       0       bounce
defer      unix  -       -       -       -       0       bounce
trace      unix  -       -       -       -       0       bounce
verify     unix  -       -       -       -       1       verify
flush      unix  n       -       -       1000?   0       flush
proxymap   unix  -       -       n       -       -       proxymap
proxywrite unix  -       -       n       -       1       proxymap
smtp       unix  -       -       -       -       -       smtp
relay      unix  -       -       -       -       -       smtp
showq      unix  n       -       -       -       -       showq
error      unix  -       -       -       -       -       error
retry      unix  -       -       -       -       -       error
discard    unix  -       -       -       -       -       discard
local      unix  -       n       n       -       -       local
virtual    unix  -       n       n       -       -       virtual
lmtp       unix  -       -       -       -       -       lmtp
anvil      unix  -       -       -       -       1       anvil
scache     unix  -       -       -       -       1       scache
uucp       unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a\$sender - \$nexthop!rmail (\$recipient)
ifmail     unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r \$nexthop (\$recipient)
bsmtp      unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t\$nexthop -f\$sender \$recipient
scalemail-backend unix	-	n	n	-	2	pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store \${nexthop} \${user} \${extension}
mailman    unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  \${nexthop} \${user}
dovecot    unix  -       n       n       -       -       pipe
  flags=DRhu user=shadowmail:shadowmail argv=/usr/lib/dovecot/deliver -f \${sender} -d \${recipient}
EOL

cat <<EOL > /etc/dovecot/dovecot.conf
!include_try /usr/share/dovecot/protocols.d/*.protocol
dict {
    l
}
!include conf.d/*.conf
!include_try local.conf

passdb {
        args = /var/mail/shadowhosts/%d/shadow
        driver = passwd-file
}

protocols = imap pop3

service auth {
        unix_listener /var/spool/postfix/private/auth {
                group = shadowmail
                mode = 0660
                user = postfix
        }
                unix_listener auth-master {
                group = shadowmail
                mode = 0600
                user = shadowmail
        }
}

userdb {
        args = /var/mail/shadowhosts/%d/passwd
        driver = passwd-file
}

protocol lda {
        auth_socket_path = /var/run/dovecot/auth-master
        hostname = $nm_domain
        mail_plugin_dir = /usr/lib/dovecot/modules
        mail_plugins = sieve
        postmaster_address = admin@$nm_domain
}
EOL

cat <<EOL > /etc/dovecot/conf.d/10-auth.conf
auth_mechanisms = plain login
disable_plaintext_auth = no

!include auth-system.conf.ext
EOL


cat <<EOL > /etc/dovecot/conf.d/10-logging.conf
plugin {

}

log_path = /var/log/dovecot
EOL

cat <<EOL > /etc/dovecot/conf.d/10-mail.conf
mail_location = maildir:/var/mail/shadowhosts/%d/%n
namespace inbox {
  inbox = yes
}

mail_privileged_group = mail

protocol !indexer-worker {

}
EOL
