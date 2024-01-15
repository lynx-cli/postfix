#!/bin/bash
echo -e "CONFIG POSTFIX"
read -p "HOSTNAME: " host_name
read -p "USERGROUP: " user_group
read -p "USERGROUP ID: " user_grpid
read -p "MAILBASE: " mail_base_rnd
mail_base="${mail_base_rnd%/}"
read -p "SSL CERT: " ssl_cert
read -p "SSL KEY: " ssl_key

groupadd -g $user_grpid $user_group
useradd -s /usr/sbin/nologin -u $user_grpid -g $user_grpid $user_group
usermod -aG $user_group postfix
usermod -aG $user_group dovecot
mkdir -p $mail_base
chown -R $user_group:$user_group $mail_base
chmod -R 775 $mail_base
touch /var/log/dovecot
chgrp $user_group /var/log/dovecot
chmod 660 /var/log/dovecot
touch /etc/postfix/shadow_domains
touch /etc/postfix/shadowmailbox
touch /etc/postfix/shadow_alias
postmap /etc/postfix/shadow_alias
echo -e "setting up /etc/postfix/main.cf - ok"
cat <<EOL > /etc/postfix/main.cf
# See /usr/share/postfix/main.cf.dist for a commented, more complete version

# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = \$myhostname ESMTP \$mail_name (Ubuntu)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# See http://www.postfix.org/COMPATIBILITY_README.html -- default to 3.6 on
# fresh installs.
compatibility_level = 3.6

# Basic parameters
myhostname = $host_name
mydomain = \$myhostname
myorigin = \$myhostname
mydestination = localhost, \$myhostname
mynetworks = 127.0.0.0/8
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all

# Virtual Mailbox parameters
virtual_mailbox_domains = /etc/postfix/shadow_domains
virtual_mailbox_base = $mail_base
virtual_mailbox_maps = hash:/etc/postfix/shadowmailbox
virtual_alias_maps = hash:/etc/postfix/shadow_alias
virtual_minimum_uid = 100
virtual_uid_maps = static:$user_grpid
virtual_gid_maps = static:$user_grpid
virtual_transport = virtual
virtual_mailbox_limit = 536870912
mailbox_size_limit = 0
message_size_limit = 10485760
dovecot_destination_recipient_limit = 1

# SASL parameters
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$mydomain
broken_sasl_auth_clients = yes

# TLS parameters
smtpd_use_tls = yes
smtpd_tls_security_level = may
smtpd_tls_auth_only = no
smtpd_tls_cert_file=$ssl_cert
smtpd_tls_key_file=$ssl_key
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtpd_tls_received_header = yes
smtpd_tls_security_level = may
smtp_tls_security_level = may
tls_random_source = dev:/dev/urandom

# Restrictions
smtpd_helo_required = no
smtpd_delay_reject = yes
strict_rfc821_envelopes = yes
disable_vrfy_command = yes

# Rate Limit
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

echo -e "setting up /etc/postfix/master.cf - ok"

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
  flags=DRhu user=$user_group:$user_group argv=/usr/lib/dovecot/deliver -f \${sender} -d \${recipient}
EOL

echo -e "setting up /etc/dovecot/dovecot.conf - ok"

cat <<EOL > /etc/dovecot/dovecot.conf
## Dovecot configuration file

# If you're in a hurry, see http://wiki2.dovecot.org/QuickConfiguration

# "doveconf -n" command gives a clean output of the changed settings. Use it
# instead of copy&pasting files when posting to the Dovecot mailing list.

# '#' character and everything after it is treated as comments. Extra spaces
# and tabs are ignored. If you want to use either of these explicitly, put the
# value inside quotes, eg.: key = "# char and trailing whitespace  "

# Most (but not all) settings can be overridden by different protocols and/or
# source/destination IPs by placing the settings inside sections, for example:
# protocol imap { }, local 127.0.0.1 { }, remote 10.0.0.0/8 { }

# Default values are shown for each setting, it's not required to uncomment
# those. These are exceptions to this though: No sections (e.g. namespace {})
# or plugin settings are added by default, they're listed only as examples.
# Paths are also just examples with the real defaults being based on configure
# options. The paths listed here are for configure --prefix=/usr
# --sysconfdir=/etc --localstatedir=/var

# Enable installed protocols
!include_try /usr/share/dovecot/protocols.d/*.protocol

# A comma separated list of IPs or hosts where to listen in for connections.
# "*" listens in all IPv4 interfaces, "::" listens in all IPv6 interfaces.
# If you want to specify non-default ports or anything more complex,
# edit conf.d/master.conf.
#listen = *, ::

# Base directory where to store runtime data.
#base_dir = /var/run/dovecot/

# Name of this instance. In multi-instance setup doveadm and other commands
# can use -i <instance_name> to select which instance is used (an alternative
# to -c <config_path>). The instance name is also added to Dovecot processes
# in ps output.
#instance_name = dovecot

# Greeting message for clients.
#login_greeting = Dovecot ready.

# Space separated list of trusted network ranges. Connections from these
# IPs are allowed to override their IP addresses and ports (for logging and
# for authentication checks). disable_plaintext_auth is also ignored for
# these networks. Typically you'd specify your IMAP proxy servers here.
#login_trusted_networks =

# Space separated list of login access check sockets (e.g. tcpwrap)
#login_access_sockets =

# With proxy_maybe=yes if proxy destination matches any of these IPs, don't do
# proxying. This isn't necessary normally, but may be useful if the destination
# IP is e.g. a load balancer's IP.
#auth_proxy_self =

# Show more verbose process titles (in ps). Currently shows user name and
# IP address. Useful for seeing who are actually using the IMAP processes
# (eg. shared mailboxes or if same uid is used for multiple accounts).
#verbose_proctitle = no

# Should all processes be killed when Dovecot master process shuts down.
# Setting this to "no" means that Dovecot can be upgraded without
# forcing existing client connections to close (although that could also be
# a problem if the upgrade is e.g. because of a security fix).
#shutdown_clients = yes

# If non-zero, run mail commands via this many connections to doveadm server,
# instead of running them directly in the same process.
#doveadm_worker_count = 0
# UNIX socket or host:port used for connecting to doveadm server
#doveadm_socket_path = doveadm-server

# Space separated list of environment variables that are preserved on Dovecot
# startup and passed down to all of its child processes. You can also give
# key=value pairs to always set specific settings.
#import_environment = TZ

##
## Dictionary server settings
##

# Dictionary can be used to store key=value lists. This is used by several
# plugins. The dictionary can be accessed either directly or though a
# dictionary server. The following dict block maps dictionary names to URIs
# when the server is used. These can then be referenced using URIs in format
# "proxy::<name>".

dict {
  #quota = mysql:/etc/dovecot/dovecot-dict-sql.conf.ext
}

# Most of the actual configuration gets included below. The filenames are
# first sorted by their ASCII value and parsed in that order. The 00-prefixes
# in filenames are intended to make it easier to understand the ordering.
!include conf.d/*.conf

# A config file can also tried to be included without giving an error if
# it's not found:
!include_try local.conf

passdb {
        args = $mail_base/%d/shadow
        driver = passwd-file
}

protocols = imap pop3

service auth {
        unix_listener /var/spool/postfix/private/auth {
                group = $user_group
                mode = 0660
                user = postfix
        }
                unix_listener auth-master {
                group = $user_group
                mode = 0600
                user = $user_group
        }
}

userdb {
        args = $mail_base/%d/passwd
        driver = passwd-file
}

protocol lda {
        auth_socket_path = /var/run/dovecot/auth-master
        hostname = $host_name
        mail_plugin_dir = /usr/lib/dovecot/modules
        mail_plugins = sieve
        postmaster_address = postmaster@stackmail.xyz
}
EOL

echo -e "setting up /etc/dovecot/conf.d/10-auth.conf - ok"

cat <<EOL > /etc/dovecot/conf.d/10-auth.conf
##
## Authentication processes
##

# Disable LOGIN command and all other plaintext authentications unless
# SSL/TLS is used (LOGINDISABLED capability). Note that if the remote IP
# matches the local IP (ie. you're connecting from the same computer), the
# connection is considered secure and plaintext authentication is allowed.
# See also ssl=required setting.
#disable_plaintext_auth = yes

# Authentication cache size (e.g. 10M). 0 means it's disabled. Note that
# bsdauth and PAM require cache_key to be set for caching to be used.
#auth_cache_size = 0
# Time to live for cached data. After TTL expires the cached record is no
# longer used, *except* if the main database lookup returns internal failure.
# We also try to handle password changes automatically: If user's previous
# authentication was successful, but this one wasn't, the cache isn't used.
# For now this works only with plaintext authentication.
#auth_cache_ttl = 1 hour
# TTL for negative hits (user not found, password mismatch).
# 0 disables caching them completely.
#auth_cache_negative_ttl = 1 hour

# Space separated list of realms for SASL authentication mechanisms that need
# them. You can leave it empty if you don't want to support multiple realms.
# Many clients simply use the first one listed here, so keep the default realm
# first.
#auth_realms =

# Default realm/domain to use if none was specified. This is used for both
# SASL realms and appending @domain to username in plaintext logins.
#auth_default_realm =

# List of allowed characters in username. If the user-given username contains
# a character not listed in here, the login automatically fails. This is just
# an extra check to make sure user can't exploit any potential quote escaping
# vulnerabilities with SQL/LDAP databases. If you want to allow all characters,
# set this value to empty.
#auth_username_chars = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@

# Username character translations before it's looked up from databases. The
# value contains series of from -> to characters. For example "#@/@" means
# that '#' and '/' characters are translated to '@'.
#auth_username_translation =

# Username formatting before it's looked up from databases. You can use
# the standard variables here, eg. %Lu would lowercase the username, %n would
# drop away the domain if it was given, or "%n-AT-%d" would change the '@' into
# "-AT-". This translation is done after auth_username_translation changes.
#auth_username_format = %Lu

# If you want to allow master users to log in by specifying the master
# username within the normal username string (ie. not using SASL mechanism's
# support for it), you can specify the separator character here. The format
# is then <username><separator><master username>. UW-IMAP uses "*" as the
# separator, so that could be a good choice.
#auth_master_user_separator =

# Username to use for users logging in with ANONYMOUS SASL mechanism
#auth_anonymous_username = anonymous

# Maximum number of dovecot-auth worker processes. They're used to execute
# blocking passdb and userdb queries (eg. MySQL and PAM). They're
# automatically created and destroyed as needed.
#auth_worker_max_count = 30

# Host name to use in GSSAPI principal names. The default is to use the
# name returned by gethostname(). Use "$ALL" (with quotes) to allow all keytab
# entries.
#auth_gssapi_hostname =

# Kerberos keytab to use for the GSSAPI mechanism. Will use the system
# default (usually /etc/krb5.keytab) if not specified. You may need to change
# the auth service to run as root to be able to read this file.
#auth_krb5_keytab =

# Do NTLM and GSS-SPNEGO authentication using Samba's winbind daemon and
# ntlm_auth helper. <doc/wiki/Authentication/Mechanisms/Winbind.txt>
#auth_use_winbind = no

# Path for Samba's ntlm_auth helper binary.
#auth_winbind_helper_path = /usr/bin/ntlm_auth

# Time to delay before replying to failed authentications.
#auth_failure_delay = 2 secs

# Require a valid SSL client certificate or the authentication fails.
#auth_ssl_require_client_cert = no

# Take the username from client's SSL certificate, using
# X509_NAME_get_text_by_NID() which returns the subject's DN's
# CommonName.
#auth_ssl_username_from_cert = no

# Space separated list of wanted authentication mechanisms:
#   plain login digest-md5 cram-md5 ntlm rpa apop anonymous gssapi otp
#   gss-spnego
# NOTE: See also disable_plaintext_auth setting.
auth_mechanisms = plain login
disable_plaintext_auth = no

##
## Password and user databases
##

#
# Password database is used to verify user's password (and nothing more).
# You can have multiple passdbs and userdbs. This is useful if you want to
# allow both system users (/etc/passwd) and virtual users to login without
# duplicating the system users into virtual database.
#
# <doc/wiki/PasswordDatabase.txt>
#
# User database specifies where mails are located and what user/group IDs
# own them. For single-UID configuration use "static" userdb.
#
# <doc/wiki/UserDatabase.txt>

#!include auth-deny.conf.ext
#!include auth-master.conf.ext

!include auth-system.conf.ext
#!include auth-sql.conf.ext
#!include auth-ldap.conf.ext
#!include auth-passwdfile.conf.ext
#!include auth-checkpassword.conf.ext
#!include auth-static.conf.ext
EOL

echo -e "setting up /etc/dovecot/conf.d/10-logging.conf - ok"

cat <<EOL > /etc/dovecot/conf.d/10-logging.conf
##
## Log destination.
##

# Log file to use for error messages. "syslog" logs to syslog,
# /dev/stderr logs to stderr.
#log_path = syslog

# Log file to use for informational messages. Defaults to log_path.
#info_log_path =
# Log file to use for debug messages. Defaults to info_log_path.
#debug_log_path =

# Syslog facility to use if you're logging to syslog. Usually if you don't
# want to use "mail", you'll use local0..local7. Also other standard
# facilities are supported.
#syslog_facility = mail

##
## Logging verbosity and debugging.
##

# Log filter is a space-separated list conditions. If any of the conditions
# match, the log filter matches (i.e. they're ORed together). Parenthesis
# are supported if multiple conditions need to be matched together.
#
# See https://doc.dovecot.org/configuration_manual/event_filter/ for details.
#
# For example: event=http_request_* AND category=error AND category=storage
#
# Filter to specify what debug logging to enable. This will eventually replace
# mail_debug and auth_debug settings.
#log_debug =

# Crash after logging a matching event. For example category=error will crash
# any time an error is logged, which can be useful for debugging.
#log_core_filter =

# Log unsuccessful authentication attempts and the reasons why they failed.
#auth_verbose = no

# In case of password mismatches, log the attempted password. Valid values are
# no, plain and sha1. sha1 can be useful for detecting brute force password
# attempts vs. user simply trying the same password over and over again.
# You can also truncate the value to n chars by appending ":n" (e.g. sha1:6).
#auth_verbose_passwords = no

# Even more verbose logging for debugging purposes. Shows for example SQL
# queries.
#auth_debug = no

# In case of password mismatches, log the passwords and used scheme so the
# problem can be debugged. Enabling this also enables auth_debug.
#auth_debug_passwords = no

# Enable mail process debugging. This can help you figure out why Dovecot
# isn't finding your mails.
#mail_debug = no

# Show protocol level SSL errors.
#verbose_ssl = no

# mail_log plugin provides more event logging for mail processes.
plugin {
  # Events to log. Also available: flag_change append
  #mail_log_events = delete undelete expunge copy mailbox_delete mailbox_rename
  # Available fields: uid, box, msgid, from, subject, size, vsize, flags
  # size and vsize are available only for expunge and copy events.
  #mail_log_fields = uid box msgid size
}

##
## Log formatting.
##

# Prefix for each line written to log file. % codes are in strftime(3)
# format.
#log_timestamp = "%b %d %H:%M:%S "

# Space-separated list of elements we want to log. The elements which have
# a non-empty variable value are joined together to form a comma-separated
# string.
#login_log_format_elements = user=<%u> method=%m rip=%r lip=%l mpid=%e %c

# Login log format. %s contains login_log_format_elements string, %$ contains
# the data we want to log.
#login_log_format = %$: %s

# Log prefix for mail processes. See doc/wiki/Variables.txt for list of
# possible variables you can use.
#mail_log_prefix = "%s(%u)<%{pid}><%{session}>: "

# Format to use for logging mail deliveries:
#  %$ - Delivery status message (e.g. "saved to INBOX")
#  %m / %{msgid} - Message-ID
#  %s / %{subject} - Subject
#  %f / %{from} - From address
#  %p / %{size} - Physical size
#  %w / %{vsize} - Virtual size
#  %e / %{from_envelope} - MAIL FROM envelope
#  %{to_envelope} - RCPT TO envelope
#  %{delivery_time} - How many milliseconds it took to deliver the mail
#  %{session_time} - How long LMTP session took, not including delivery_time
#  %{storage_id} - Backend-specific ID for mail, e.g. Maildir filename
#deliver_log_format = msgid=%m: %$

log_path = /var/log/dovecot
EOL

echo -e "setting up /etc/dovecot/conf.d/10-mail.conf - ok"

cat <<EOL > /etc/dovecot/conf.d/10-mail.conf
##
## Mailbox locations and namespaces
##

# Location for users' mailboxes. The default is empty, which means that Dovecot
# tries to find the mailboxes automatically. This won't work if the user
# doesn't yet have any mail, so you should explicitly tell Dovecot the full
# location.
#
# If you're using mbox, giving a path to the INBOX file (eg. /var/mail/%u)
# isn't enough. You'll also need to tell Dovecot where the other mailboxes are
# kept. This is called the "root mail directory", and it must be the first
# path given in the mail_location setting.
#
# There are a few special variables you can use, eg.:
#
#   %u - username
#   %n - user part in user@domain, same as %u if there's no domain
#   %d - domain part in user@domain, empty if there's no domain
#   %h - home directory
#
# See doc/wiki/Variables.txt for full list. Some examples:
#
mail_location = maildir:$mail_base/%d/%n
#   mail_location = maildir:~/Maildir
#   mail_location = mbox:~/mail:INBOX=/var/mail/%u
#   mail_location = mbox:/var/mail/%d/%1n/%n:INDEX=/var/indexes/%d/%1n/%n
#
# <doc/wiki/MailLocation.txt>
#
#  mail_location = mbox:~/mail:INBOX=/var/mail/%u

# If you need to set multiple mailbox locations or want to change default
# namespace settings, you can do it by defining namespace sections.
#
# You can have private, shared and public namespaces. Private namespaces
# are for user's personal mails. Shared namespaces are for accessing other
# users' mailboxes that have been shared. Public namespaces are for shared
# mailboxes that are managed by sysadmin. If you create any shared or public
# namespaces you'll typically want to enable ACL plugin also, otherwise all
# users can access all the shared mailboxes, assuming they have permissions
# on filesystem level to do so.
namespace inbox {
  # Namespace type: private, shared or public
  #type = private

  # Hierarchy separator to use. You should use the same separator for all
  # namespaces or some clients get confused. '/' is usually a good one.
  # The default however depends on the underlying mail storage format.
  #separator =

  # Prefix required to access this namespace. This needs to be different for
  # all namespaces. For example "Public/".
  #prefix =

  # Physical location of the mailbox. This is in same format as
  # mail_location, which is also the default for it.
  #location =

  # There can be only one INBOX, and this setting defines which namespace
  # has it.
  inbox = yes

  # If namespace is hidden, it's not advertised to clients via NAMESPACE
  # extension. You'll most likely also want to set list=no. This is mostly
  # useful when converting from another server with different namespaces which
  # you want to deprecate but still keep working. For example you can create
  # hidden namespaces with prefixes "~/mail/", "~%u/mail/" and "mail/".
  #hidden = no

  # Show the mailboxes under this namespace with LIST command. This makes the
  # namespace visible for clients that don't support NAMESPACE extension.
  # "children" value lists child mailboxes, but hides the namespace prefix.
  #list = yes

  # Namespace handles its own subscriptions. If set to "no", the parent
  # namespace handles them (empty prefix should always have this as "yes")
  #subscriptions = yes

  # See 15-mailboxes.conf for definitions of special mailboxes.
}

# Example shared namespace configuration
#namespace {
  #type = shared
  #separator = /

  # Mailboxes are visible under "shared/user@domain/"
  # %%n, %%d and %%u are expanded to the destination user.
  #prefix = shared/%%u/

  # Mail location for other users' mailboxes. Note that %variables and ~/
  # expands to the logged in user's data. %%n, %%d, %%u and %%h expand to the
  # destination user's data.
  #location = maildir:%%h/Maildir:INDEX=~/Maildir/shared/%%u

  # Use the default namespace for saving subscriptions.
  #subscriptions = no

  # List the shared/ namespace only if there are visible shared mailboxes.
  #list = children
#}
# Should shared INBOX be visible as "shared/user" or "shared/user/INBOX"?
#mail_shared_explicit_inbox = no

# System user and group used to access mails. If you use multiple, userdb
# can override these by returning uid or gid fields. You can use either numbers
# or names. <doc/wiki/UserIds.txt>
#mail_uid =
#mail_gid =

# Group to enable temporarily for privileged operations. Currently this is
# used only with INBOX when either its initial creation or dotlocking fails.
# Typically this is set to "mail" to give access to /var/mail.
mail_privileged_group = mail

# Grant access to these supplementary groups for mail processes. Typically
# these are used to set up access to shared mailboxes. Note that it may be
# dangerous to set these if users can create symlinks (e.g. if "mail" group is
# set here, ln -s /var/mail ~/mail/var could allow a user to delete others'
# mailboxes, or ln -s /secret/shared/box ~/mail/mybox would allow reading it).
#mail_access_groups =

# Allow full filesystem access to clients. There's no access checks other than
# what the operating system does for the active UID/GID. It works with both
# maildir and mboxes, allowing you to prefix mailboxes names with eg. /path/
# or ~user/.
#mail_full_filesystem_access = no

# Dictionary for key=value mailbox attributes. This is used for example by
# URLAUTH and METADATA extensions.
#mail_attribute_dict =

# A comment or note that is associated with the server. This value is
# accessible for authenticated users through the IMAP METADATA server
# entry "/shared/comment".
#mail_server_comment = ""

# Indicates a method for contacting the server administrator. According to
# RFC 5464, this value MUST be a URI (e.g., a mailto: or tel: URL), but that
# is currently not enforced. Use for example mailto:admin@example.com. This
# value is accessible for authenticated users through the IMAP METADATA server
# entry "/shared/admin".
#mail_server_admin =

##
## Mail processes
##

# Don't use mmap() at all. This is required if you store indexes to shared
# filesystems (NFS or clustered filesystem).
#mmap_disable = no

# Rely on O_EXCL to work when creating dotlock files. NFS supports O_EXCL
# since version 3, so this should be safe to use nowadays by default.
#dotlock_use_excl = yes

# When to use fsync() or fdatasync() calls:
#   optimized (default): Whenever necessary to avoid losing important data
#   always: Useful with e.g. NFS when write()s are delayed
#   never: Never use it (best performance, but crashes can lose data)
#mail_fsync = optimized

# Locking method for index files. Alternatives are fcntl, flock and dotlock.
# Dotlocking uses some tricks which may create more disk I/O than other locking
# methods. NFS users: flock doesn't work, remember to change mmap_disable.
#lock_method = fcntl

# Directory where mails can be temporarily stored. Usually it's used only for
# mails larger than >= 128 kB. It's used by various parts of Dovecot, for
# example LDA/LMTP while delivering large mails or zlib plugin for keeping
# uncompressed mails.
#mail_temp_dir = /tmp

# Valid UID range for users, defaults to 500 and above. This is mostly
# to make sure that users can't log in as daemons or other system users.
# Note that denying root logins is hardcoded to dovecot binary and can't
# be done even if first_valid_uid is set to 0.
#first_valid_uid = 500
#last_valid_uid = 0

# Valid GID range for users, defaults to non-root/wheel. Users having
# non-valid GID as primary group ID aren't allowed to log in. If user
# belongs to supplementary groups with non-valid GIDs, those groups are
# not set.
#first_valid_gid = 1
#last_valid_gid = 0

# Maximum allowed length for mail keyword name. It's only forced when trying
# to create new keywords.
#mail_max_keyword_length = 50

# ':' separated list of directories under which chrooting is allowed for mail
# processes (ie. /var/mail will allow chrooting to /var/mail/foo/bar too).
# This setting doesn't affect login_chroot, mail_chroot or auth chroot
# settings. If this setting is empty, "/./" in home dirs are ignored.
# WARNING: Never add directories here which local users can modify, that
# may lead to root exploit. Usually this should be done only if you don't
# allow shell access for users. <doc/wiki/Chrooting.txt>
#valid_chroot_dirs =

# Default chroot directory for mail processes. This can be overridden for
# specific users in user database by giving /./ in user's home directory
# (eg. /home/./user chroots into /home). Note that usually there is no real
# need to do chrooting, Dovecot doesn't allow users to access files outside
# their mail directory anyway. If your home directories are prefixed with
# the chroot directory, append "/." to mail_chroot. <doc/wiki/Chrooting.txt>
#mail_chroot =

# UNIX socket path to master authentication server to find users.
# This is used by imap (for shared users) and lda.
#auth_socket_path = /var/run/dovecot/auth-userdb

# Directory where to look up mail plugins.
#mail_plugin_dir = /usr/lib/dovecot/modules

# Space separated list of plugins to load for all services. Plugins specific to
# IMAP, LDA, etc. are added to this list in their own .conf files.
#mail_plugins =

##
## Mailbox handling optimizations
##

# Mailbox list indexes can be used to optimize IMAP STATUS commands. They are
# also required for IMAP NOTIFY extension to be enabled.
#mailbox_list_index = yes

# Trust mailbox list index to be up-to-date. This reduces disk I/O at the cost
# of potentially returning out-of-date results after e.g. server crashes.
# The results will be automatically fixed once the folders are opened.
#mailbox_list_index_very_dirty_syncs = yes

# Should INBOX be kept up-to-date in the mailbox list index? By default it's
# not, because most of the mailbox accesses will open INBOX anyway.
#mailbox_list_index_include_inbox = no

# The minimum number of mails in a mailbox before updates are done to cache
# file. This allows optimizing Dovecot's behavior to do less disk writes at
# the cost of more disk reads.
#mail_cache_min_mail_count = 0

# When IDLE command is running, mailbox is checked once in a while to see if
# there are any new mails or other changes. This setting defines the minimum
# time to wait between those checks. Dovecot can also use inotify and
# kqueue to find out immediately when changes occur.
#mailbox_idle_check_interval = 30 secs

# Save mails with CR+LF instead of plain LF. This makes sending those mails
# take less CPU, especially with sendfile() syscall with Linux and FreeBSD.
# But it also creates a bit more disk I/O which may just make it slower.
# Also note that if other software reads the mboxes/maildirs, they may handle
# the extra CRs wrong and cause problems.
#mail_save_crlf = no

# Max number of mails to keep open and prefetch to memory. This only works with
# some mailbox formats and/or operating systems.
#mail_prefetch_count = 0

# How often to scan for stale temporary files and delete them (0 = never).
# These should exist only after Dovecot dies in the middle of saving mails.
#mail_temp_scan_interval = 1w

# How many slow mail accesses sorting can perform before it returns failure.
# With IMAP the reply is: NO [LIMIT] Requested sort would have taken too long.
# The untagged SORT reply is still returned, but it's likely not correct.
#mail_sort_max_read_count = 0

protocol !indexer-worker {
  # If folder vsize calculation requires opening more than this many mails from
  # disk (i.e. mail sizes aren't in cache already), return failure and finish
  # the calculation via indexer process. Disabled by default. This setting must
  # be 0 for indexer-worker processes.
  #mail_vsize_bg_after_count = 0
}

##
## Maildir-specific settings
##

# By default LIST command returns all entries in maildir beginning with a dot.
# Enabling this option makes Dovecot return only entries which are directories.
# This is done by stat()ing each entry, so it causes more disk I/O.
# (For systems setting struct dirent->d_type, this check is free and it's
# done always regardless of this setting)
#maildir_stat_dirs = no

# When copying a message, do it with hard links whenever possible. This makes
# the performance much better, and it's unlikely to have any side effects.
#maildir_copy_with_hardlinks = yes

# Assume Dovecot is the only MUA accessing Maildir: Scan cur/ directory only
# when its mtime changes unexpectedly or when we can't find the mail otherwise.
#maildir_very_dirty_syncs = no

# If enabled, Dovecot doesn't use the S=<size> in the Maildir filenames for
# getting the mail's physical size, except when recalculating Maildir++ quota.
# This can be useful in systems where a lot of the Maildir filenames have a
# broken size. The performance hit for enabling this is very small.
#maildir_broken_filename_sizes = no

# Always move mails from new/ directory to cur/, even when the \Recent flags
# aren't being reset.
#maildir_empty_new = no

##
## mbox-specific settings
##

# Which locking methods to use for locking mbox. There are four available:
#  dotlock: Create <mailbox>.lock file. This is the oldest and most NFS-safe
#           solution. If you want to use /var/mail/ like directory, the users
#           will need write access to that directory.
#  dotlock_try: Same as dotlock, but if it fails because of permissions or
#               because there isn't enough disk space, just skip it.
#  fcntl  : Use this if possible. Works with NFS too if lockd is used.
#  flock  : May not exist in all systems. Doesn't work with NFS.
#  lockf  : May not exist in all systems. Doesn't work with NFS.
#
# You can use multiple locking methods; if you do the order they're declared
# in is important to avoid deadlocks if other MTAs/MUAs are using multiple
# locking methods as well. Some operating systems don't allow using some of
# them simultaneously.
#
# The Debian value for mbox_write_locks differs from upstream Dovecot. It is
# changed to be compliant with Debian Policy (section 11.6) for NFS safety.
#       Dovecot: mbox_write_locks = dotlock fcntl
#       Debian:  mbox_write_locks = fcntl dotlock
#
#mbox_read_locks = fcntl
#mbox_write_locks = fcntl dotlock

# Maximum time to wait for lock (all of them) before aborting.
#mbox_lock_timeout = 5 mins

# If dotlock exists but the mailbox isn't modified in any way, override the
# lock file after this much time.
#mbox_dotlock_change_timeout = 2 mins

# When mbox changes unexpectedly we have to fully read it to find out what
# changed. If the mbox is large this can take a long time. Since the change
# is usually just a newly appended mail, it'd be faster to simply read the
# new mails. If this setting is enabled, Dovecot does this but still safely
# fallbacks to re-reading the whole mbox file whenever something in mbox isn't
# how it's expected to be. The only real downside to this setting is that if
# some other MUA changes message flags, Dovecot doesn't notice it immediately.
# Note that a full sync is done with SELECT, EXAMINE, EXPUNGE and CHECK
# commands.
#mbox_dirty_syncs = yes

# Like mbox_dirty_syncs, but don't do full syncs even with SELECT, EXAMINE,
# EXPUNGE or CHECK commands. If this is set, mbox_dirty_syncs is ignored.
#mbox_very_dirty_syncs = no

# Delay writing mbox headers until doing a full write sync (EXPUNGE and CHECK
# commands and when closing the mailbox). This is especially useful for POP3
# where clients often delete all mails. The downside is that our changes
# aren't immediately visible to other MUAs.
#mbox_lazy_writes = yes

# If mbox size is smaller than this (e.g. 100k), don't write index files.
# If an index file already exists it's still read, just not updated.
#mbox_min_index_size = 0

# Mail header selection algorithm to use for MD5 POP3 UIDLs when
# pop3_uidl_format=%m. For backwards compatibility we use apop3d inspired
# algorithm, but it fails if the first Received: header isn't unique in all
# mails. An alternative algorithm is "all" that selects all headers.
#mbox_md5 = apop3d

##
## mdbox-specific settings
##

# Maximum dbox file size until it's rotated.
#mdbox_rotate_size = 10M

# Maximum dbox file age until it's rotated. Typically in days. Day begins
# from midnight, so 1d = today, 2d = yesterday, etc. 0 = check disabled.
#mdbox_rotate_interval = 0

# When creating new mdbox files, immediately preallocate their size to
# mdbox_rotate_size. This setting currently works only in Linux with some
# filesystems (ext4, xfs).
#mdbox_preallocate_space = no

##
## Mail attachments
##

# sdbox and mdbox support saving mail attachments to external files, which
# also allows single instance storage for them. Other backends don't support
# this for now.

# Directory root where to store mail attachments. Disabled, if empty.
#mail_attachment_dir =

# Attachments smaller than this aren't saved externally. It's also possible to
# write a plugin to disable saving specific attachments externally.
#mail_attachment_min_size = 128k

# Filesystem backend to use for saving attachments:
#  posix : No SiS done by Dovecot (but this might help FS's own deduplication)
#  sis posix : SiS with immediate byte-by-byte comparison during saving
#  sis-queue posix : SiS with delayed comparison and deduplication
#mail_attachment_fs = sis posix

# Hash format to use in attachment filenames. You can add any text and
# variables: %{md4}, %{md5}, %{sha1}, %{sha256}, %{sha512}, %{size}.
# Variables can be truncated, e.g. %{sha256:80} returns only first 80 bits
#mail_attachment_hash = %{sha1}

# Settings to control adding \$HasAttachment or \$HasNoAttachment keywords.
# By default, all MIME parts with Content-Disposition=attachment, or inlines
# with filename parameter are consired attachments.
#   add-flags - Add the keywords when saving new mails or when fetching can
#      do it efficiently.
#   content-type=type or !type - Include/exclude content type. Excluding will
#     never consider the matched MIME part as attachment. Including will only
#     negate an exclusion (e.g. content-type=!foo/* content-type=foo/bar).
#   exclude-inlined - Exclude any Content-Disposition=inline MIME part.
#mail_attachment_detection_options =
EOL

echo -e "setting up /etc/dovecot/conf.d/10-ssl.conf - ok"

cat <<EOL > /etc/dovecot/conf.d/10-ssl.conf
##
## SSL settings
##

# SSL/TLS support: yes, no, required. <doc/wiki/SSL.txt>
ssl = yes

# PEM encoded X.509 SSL/TLS certificate and private key. They're opened before
# dropping root privileges, so keep the key file unreadable by anyone but
# root. Included doc/mkcert.sh can be used to easily generate self-signed
# certificate, just make sure to update the domains in dovecot-openssl.cnf
ssl_cert = <$ssl_cert
ssl_key = <$ssl_key

# If key file is password protected, give the password here. Alternatively
# give it when starting dovecot with -p parameter. Since this file is often
# world-readable, you may want to place this setting instead to a different
# root owned 0600 file by using ssl_key_password = <path.
#ssl_key_password =

# PEM encoded trusted certificate authority. Set this only if you intend to use
# ssl_verify_client_cert=yes. The file should contain the CA certificate(s)
# followed by the matching CRL(s). (e.g. ssl_ca = </etc/ssl/certs/ca.pem)
#ssl_ca =

# Require that CRL check succeeds for client certificates.
#ssl_require_crl = yes

# Directory and/or file for trusted SSL CA certificates. These are used only
# when Dovecot needs to act as an SSL client (e.g. imapc backend or
# submission service). The directory is usually /etc/ssl/certs in
# Debian-based systems and the file is /etc/pki/tls/cert.pem in
# RedHat-based systems. Note that ssl_client_ca_file isn't recommended with
# large CA bundles, because it leads to excessive memory usage.
#ssl_client_ca_dir =
#ssl_client_ca_dir = /etc/ssl/certs
#ssl_client_ca_file =

# Require valid cert when connecting to a remote server
#ssl_client_require_valid_cert = yes

# Request client to send a certificate. If you also want to require it, set
# auth_ssl_require_client_cert=yes in auth section.
#ssl_verify_client_cert = no

# Which field from certificate to use for username. commonName and
# x500UniqueIdentifier are the usual choices. You'll also need to set
# auth_ssl_username_from_cert=yes.
#ssl_cert_username_field = commonName

# SSL DH parameters
# Generate new params with - openssl dhparam -out /etc/dovecot/dh.pem 4096
# Or migrate from old ssl-parameters.dat file with the command dovecot
# gives on startup when ssl_dh is unset.
#ssl_dh = </usr/share/dovecot/dh.pem

# Minimum SSL protocol version to use. Potentially recognized values are SSLv3,
# TLSv1, TLSv1.1, TLSv1.2 and TLSv1.3, depending on the OpenSSL version used.
#
# Dovecot also recognizes values ANY and LATEST. ANY matches with any protocol
# version, and LATEST matches with the latest version supported by library.
#ssl_min_protocol = TLSv1.2

# SSL ciphers to use, the default is:
#ssl_cipher_list = ALL:!kRSA:!SRP:!kDHd:!DSS:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4:!ADH:!LOW@STRENGTH
# To disable non-EC DH, use:
#ssl_cipher_list = ALL:!DH:!kRSA:!SRP:!kDHd:!DSS:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4:!ADH:!LOW@STRENGTH

# Colon separated list of elliptic curves to use. Empty value (the default)
# means use the defaults from the SSL library. P-521:P-384:P-256 would be an
# example of a valid value.
#ssl_curve_list =

# Prefer the server's order of ciphers over client's.
#ssl_prefer_server_ciphers = no

# SSL crypto device to use, for valid values run "openssl engine"
#ssl_crypto_device =

# SSL extra options. Currently supported options are:
#   compression - Enable compression.
#   no_ticket - Disable SSL session tickets.
#ssl_options =
EOL


cat <<EOL > addom.sh
ADDR=\$1;
BASEDIR="\$(postconf | grep ^virtual_mailbox_base | cut -f3 -d' ')";
mkdir -p \$BASEDIR/\$ADDR
chown -R $user_group:$user_group \$BASEDIR
chmod -R 775 \$BASEDIR

echo "\$ADDR " >> /etc/postfix/shadow_domains
echo "root@\$ADDR admin@\$ADDR\n" >> /etc/postfix/shadow_alias
postmap /etc/postfix/shadow_alias
EOL

cat <<EOL > addmail.sh
USERNAME=\$(echo "\$1" | cut -f1 -d@);
DOMAIN=\$(echo "\$1" | cut -f2 -d@);
ADDRESS=\$1;
PASSWD=\$2;

BASEDIR="\$(postconf | grep ^virtual_mailbox_base | cut -f3 -d' ')";

if [ -f /etc/postfix/shadowmailbox ]
then
	echo "Adding Postfix user configuration..."
	echo \$ADDRESS \$DOMAIN/\$USERNAME/ >> /etc/postfix/shadowmailbox
	postmap /etc/postfix/shadowmailbox

	if [ \$? -eq 0 ]
	then
		echo "Adding Dovecot user configuration..."
		echo \$ADDRESS::$user_grpid:$user_grpid::\$BASEDIR/\$DOMAIN/\$ADDRESS>> \$BASEDIR/\$DOMAIN/passwd
		echo \$ADDRESS":"\$(doveadm pw -p \$PASSWD) >> \$BASEDIR/\$DOMAIN/shadow
		chown $user_group:$user_group \$BASEDIR/\$DOMAIN/passwd && chmod 775 \$BASEDIR/\$DOMAIN/passwd
		chown $user_group:$user_group \$BASEDIR/\$DOMAIN/shadow && chmod 775 \$BASEDIR/\$DOMAIN/shadow
		/etc/init.d/postfix reload
	fi
fi
EOL

systemctl restart postfix
systemctl restart dovecot
