#! /bin/bash

#############################################################################
#                                                                           #
# Author:       Martin Boller                                               #
#                                                                           #
# Email:        martin                                                      #
# Last Update:  2021-11-10                                                  #
# Version:      2.00                                                        #
#                                                                           #
# Changes:      Initial Version (1.00)                                      #
#               Some cron stuff (1.50)                                      #
#               IPTABLES FW (2.00)                                          #
#                                                                           #
# Info:                                                                     #
#                                                                           #
#                                                                           #
# Instruction:  Run this script as root on a fully updated                  #
#               Debian 10 (Buster) or Debian 11 (Bullseye)                  #
#                                                                           #
#############################################################################


install_prerequisites() {
    /usr/bin/logger 'install_prerequisites' -t 'erambaCE-2021-11-12';
    echo -e "\e[1;32m--------------------------------------------\e[0m";
    echo -e "\e[1;32mInstalling Prerequisite packages\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    # OS Version
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
    /usr/bin/logger "Operating System: $OS Version: $VER" -t 'erambaCE-2021-11-12';
    echo -e "\e[1;32mOperating System: $OS Version: $VER\e[0m";
  # Install prerequisites
    apt-get update 2>&1 1>/dev/null;
    # Install some basic tools on a Debian net install
    /usr/bin/logger '..Install some basic tools on a Debian net install' -t 'erambaCE-2021-11-12';
    #apt-get -y install --fix-policy;
    apt-get -y install adduser wget whois unzip apt-transport-https ca-certificates curl gnupg2 software-properties-common dnsutils \
        iptables dirmngr --install-recommends 2>&1 1>/dev/null;
    # Set correct locale
    locale-gen 2>&1 1>/dev/null;
    update-locale 2>&1 1>/dev/null;
    # Install other preferences and clean up APT
    /usr/bin/logger '....Install some preferences on Debian and clean up APT' -t 'erambaCE-2021-11-12';
    apt-get -y install bash-completion 2>&1 1>/dev/null;
    # Install SUDO
    apt-get -y install sudo 2>&1 1>/dev/null;
    # A little apt 
    apt-get -y install --fix-missing 2>&1 1>/dev/null;
    apt-get update 2>&1 1>/dev/null;
    apt-get -y full-upgrade 2>&1 1>/dev/null;
    apt-get -y autoremove --purge 2>&1 1>/dev/null;
    apt-get -y autoclean 2>&1 1>/dev/null;
    apt-get -y clean 2>&1 1>/dev/null;
    # Python pip packages
    python3 -m pip install --upgrade pip 2>&1 1>/dev/null;
    /usr/bin/logger 'install_prerequisites finished' -t 'erambaCE-2021-11-12';
}

install_apache() {
    /usr/bin/logger 'install_apache()' -t 'erambaCE-2021-11-12';
    apt-get -y install apache2 apache2-utils 2>&1 1>/dev/null;
    /usr/bin/logger 'install_apache() finished' -t 'erambaCE-2021-11-12';
}

install_php() {
    /usr/bin/logger 'install_php()' -t 'erambaCE-2021-11-12';
    apt-get -y install php php-mysql libapache2-mod-php php-cli php-curl php-ldap php-mbstring php-gd php-exif php-intl php-xml php-zip \
        php-bz2 php-sqlite3 php-common 2>&1 1>/dev/null;
    /usr/bin/logger 'install_php() finished' -t 'erambaCE-2021-11-12';
}

install_mariadb() {
    /usr/bin/logger 'install_mariadb()' -t 'erambaCE-2021-11-12';
    apt-get -y install mariadb-server 2>&1 1>/dev/null;
    /usr/bin/logger 'install_mariadb() finished' -t 'erambaCE-2021-11-12';
}

configure_mariadb() {
    /usr/bin/logger 'configure_mariadb()' -t 'erambaCE-2021-11-12';
    mysql_secure_installation;
    /usr/bin/logger 'configure_mariadb() finished' -t 'erambaCE-2021-11-12';
}

install_pdf_tools() {
    /usr/bin/logger 'install_pdf_tools()' -t 'erambaCE-2021-11-12';
    cd /tmp/;
    wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox_0.12.6-1.buster_amd64.deb -O ./wkhtmltox.deb 2>&1 1>/dev/null;
    apt-get -y install ./wkhtmltox.deb -f  2>&1 1>/dev/null;
    /usr/bin/logger 'install_pdf_tools() finished' -t 'erambaCE-2021-11-12';
}

install_eramba() {    
    /usr/bin/logger 'install_eramba()' -t 'erambaCE-2021-11-12';
    echo -e "\e[1;32mPreparing Eramba Source files\e[0m";
    mkdir -p /var/www/html/;
    mkdir -p /tmp/eramba/;
    cd /tmp/eramba;
    wget https://downloadseramba.s3-eu-west-1.amazonaws.com/CommunityTGZ/latest.tgz 2>&1 1>/dev/null;
    sync;
    tar -xzf latest.tgz -C /var/www/html/;
    sync;
    /usr/bin/logger 'install_eramba finished' -t 'erambaCE-2021-11-12';
}

generate_certificates() {
    /usr/bin/logger 'generate_certificates()' -t 'erambaCE-2021-11-12';
    mkdir -p /etc/apache2/certs/;

    # organization name
    # (see also https://www.switch.ch/pki/participants/)
    export ORGNAME=eramba-community
    # the fully qualified server (or service) name, change if other servicename than hostname
    export FQDN=$HOSTNAME;
    # Local information
    export ISOCOUNTRY=DK;
    export PROVINCE=Denmark;
    export LOCALITY=Aabenraa
    # subjectAltName entries: to add DNS aliases to the CSR, delete
    # the '#' character in the ALTNAMES line, and change the subsequent
    # 'DNS:' entries accordingly. Please note: all DNS names must
    # resolve to the same IP address as the FQDN.
    export ALTNAMES=DNS:$HOSTNAME   # , DNS:bar.example.org , DNS:www.foo.example.org

    cat << __EOF__ > ./openssl.cnf
## Request for $FQDN
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
encrypt_key = no
distinguished_name = dn
req_extensions = req_ext

[ dn ]
countryName         = $ISOCOUNTRY
stateOrProvinceName = $PROVINCE
localityName        = $LOCALITY
organizationName    = $ORGNAME
CN = $FQDN

[ req_ext ]
subjectAltName = $ALTNAMES
__EOF__
    sync;
    # generate Certificate Signing Request to send to corp PKI
    openssl req -new -config openssl.cnf -keyout /etc/apache2/certs/$HOSTNAME.key -out /etc/apache2/certs/$HOSTNAME.csr
    # generate self-signed certificate (remove when CSR can be sent to Corp PKI)
    openssl x509 -in /etc/apache2/certs/$HOSTNAME.csr -out /etc/apache2/certs/$HOSTNAME.crt -req -signkey /etc/apache2/certs/$HOSTNAME.key -days 365
    chmod 600 /etc/apache2/certs/$HOSTNAME.key
    /usr/bin/logger 'generate_certificates() finished' -t 'erambaCE-2021-11-12';
}

prepare_nix() {
    /usr/bin/logger 'prepare_nix()' -t 'gse-21.4';
    echo -e "\e[1;32mCreating Users, configuring sudoers, and setting locale\e[0m";
    # set desired locale
    localectl set-locale en_US.UTF-8;
    # Configure MOTD
    BUILDDATE=$(date +%Y-%m-%d)
    cat << __EOF__ >> /etc/motd
           
*******************************************
***                                     ***
***            Eramba                   ***
***    ------------------------         ***          
***      Automated Install              ***
***   Eramba Community Edition          ***
***     Build date $BUILDDATE           ***
***                                     ***
********************||*********************
             (\__/) ||
             (•ㅅ•) ||
            /  　  づ
     Automated install v1.5
            2021-11-08

__EOF__
    # do not show motd twice
    sed -ie 's/session    optional     pam_motd.so  motd=\/etc\/motd/#session    optional     pam_motd.so  motd=\/etc\/motd/' /etc/pam.d/sshd
    sync;
    /usr/bin/logger 'prepare_nix() finished' -t 'erambaCE-2021-11-12';
}

prepare_mariadb() {
    /usr/bin/logger 'prepare_mariadb()' -t 'erambaCE-2021-11-12';
    # If /root/.my.cnf exists then it won't ask for root password
    export dbusername=eramba;
    #read -s -p "Enter Password for MariaDB user $dbusername: " userpass
    # Create random password 64 chars
    export userpass="$(< /dev/urandom tr -dc A-Za-z0-9_ | head -c 64)";
    export dbname=eramba_data;
    export charset=utf8;
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    echo -e "\e[1;32mCreating Database $dbname\e[0m"
    mysql -e "CREATE DATABASE ${dbname} /*\!40100 DEFAULT CHARACTER SET ${charset} */;"
    echo -e "\e[1;32mDatabase successfully created\e[0m"
    /usr/bin/logger "Database $dbname successfully created" -t 'erambaCE-2021-11-12';
    echo -e "\e[1;32mCreating user $dbusername .....\e[0m"
    mysql -e "CREATE USER ${dbusername}@localhost IDENTIFIED BY '${userpass}';"
    echo -e "\e[1;32mUser $dbusername successfully created\e[0m"
    /usr/bin/logger "User $dbusername successfully created" -t 'erambaCE-2021-11-12';
    echo -e "\e[1;32mGranting ALL privileges on ${dbname} to ${dbusername}"
    mysql -e "GRANT ALL PRIVILEGES ON ${dbname}.* TO '${dbusername}'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    echo -e "\e[1;32mPrivileges successfully created for User: $dbusername on Database: $dbname\e[0m"
    /usr/bin/logger "Privileges granted to user $dbusername on database $dbname" -t 'erambaCE-2021-11-12';
    echo -e "\e[1;32mCreating Eramba database schema on ${dbname}";
    for file in /var/www/html/eramba_community/app/Config/db_schema/*.sql; do cat "$file"; done | mysql eramba_data
    /usr/bin/logger "Schema created on database $dbname" -t 'erambaCE-2021-11-12';
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    export default='$default'
    cat << __EOF__ > /var/www/html/eramba_community/app/Config/database.php;
<?php
class DATABASE_CONFIG {

	public $default = array(
		'datasource' => 'Database/Mysql',
		'persistent' => false,
		'host' => 'localhost',
		'login' => '$dbusername',
		'password' => '$userpass',
		'database' => '$dbname',
		'prefix' => '',
		'encoding' => 'utf8',
	);
}
__EOF__
    /usr/bin/logger 'prepare_mariadb() finished' -t 'erambaCE-2021-11-12';
}

start_services() {
    /usr/bin/logger 'start_services' -t 'erambaCE-2021-11-12';
    # Load new/changed systemd-unitfiles
    systemctl daemon-reload 2>&1 1>/dev/null;
    # Enable services
    systemctl enable apache2 2>&1 1>/dev/null;
    systemctl enable mariadb 2>&1 1>/dev/null;
    # Start GSE units
    systemctl restart mariadb 2>&1 1>/dev/null;
    systemctl restart apache2 2>&1 1>/dev/null;
    /usr/bin/logger 'start_services finished' -t 'erambaCE-2021-11-12';
}

check_services() {
    /usr/bin/logger 'check_services' -t 'erambaCE-2021-11-12';
    # Check status of critical services
    # Apache
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    echo -e "\e[1;32mChecking core daemons for Eramba......\e[0m";
    if systemctl is-active --quiet apache2.service;
        then
            echo -e "\e[1;32mapache webserver started successfully";
            /usr/bin/logger 'apache webserver started successfully' -t 'erambaCE-2021-11-12';
        else
            echo -e "\e[1;31mapache webserver FAILED!\e[0m";
            /usr/bin/logger 'apache webserver FAILED' -t 'erambaCE-2021-11-12';
    fi
    # mariadb.service
    if systemctl is-active --quiet mariadb.service;
        then
            echo -e "\e[1;32mmariadb.service started successfully";
            /usr/bin/logger 'mariadb.service started successfully' -t 'erambaCE-2021-11-12';
        else
            echo -e "\e[1;31mmariadb.service FAILED!\e[0m";
            /usr/bin/logger "mariadb.service FAILED!" -t 'erambaCE-2021-11-12';
    fi
    /usr/bin/logger 'check_services finished' -t 'erambaCE-2021-11-12';
}

configure_mariadb() {
    /usr/bin/logger 'configure_mariadb' -t 'erambaCE-2021-11-12';
    cat << __EOF__ >> /etc/mysql/my.cnf 
[mysqld]
sql_mode="NO_ENGINE_SUBSTITUTION"
max_allowed_packet="128000000"
innodb_lock_wait_timeout="200"
__EOF__
    /usr/bin/logger 'configure_mariadb finished' -t 'erambaCE-2021-11-12';
}

configure_php() {
    /usr/bin/logger 'configure_php()' -t 'erambaCE-2021-11-12';
    # Apache
    sed -i -e "s/upload_max_filesize = [0-9]\{1,\}M/upload_max_filesize = 50M/" /etc/php/7.4/apache2/php.ini 2>&1 1>/dev/null
    sed -i -e "s/memory_limit = [0-9]\{1,\}M/memory_limit = 2048M/" /etc/php/7.4/apache2/php.ini 2>&1 1>/dev/null
    sed -i -e "s/post_max_size = [0-9]\{1,\}M/post_max_size = 500M/" /etc/php/7.4/apache2/php.ini 2>&1 1>/dev/null
    sed -i -e "s/file_uploads = Off/post_max_size = On/" /etc/php/7.4/apache2/php.ini 2>&1 1>/dev/null
    sed -i -e "s/max_execution_time = [0-9]\{1,\}/max_execution_time = 500/" /etc/php/7.4/apache2/php.ini 2>&1 1>/dev/null
    sed -i -e "s/allow_url_fopen = Off/allow_url_fopen = On/" /etc/php/7.4/apache2/php.ini 2>&1 1>/dev/null
    sed -i -e "s/;max_input_vars = [0-9]\{1,\}/max_input_vars = 5000/" /etc/php/7.4/apache2/php.ini 2>&1 1>/dev/null
    sed -i -e "s/max_input_time = [0-9]\{1,\}/max_input_time = 600/" /etc/php/7.4/apache2/php.ini 2>&1 1>/dev/null
    # CLI must be same values
    sed -i -e "s/upload_max_filesize = [0-9]\{1,\}M/upload_max_filesize = 50M/" /etc/php/7.4/cli/php.ini 2>&1 1>/dev/null
    sed -i -e "s/memory_limit = -[0-9]\{1,\}/memory_limit = 2048M/" /etc/php/7.4/cli/php.ini 2>&1 1>/dev/null
    sed -i -e "s/post_max_size = [0-9]\{1,\}M/post_max_size = 500M/" /etc/php/7.4/cli/php.ini 2>&1 1>/dev/null
    sed -i -e "s/file_uploads = Off/post_max_size = On/" /etc/php/7.4/cli/php.ini 2>&1 1>/dev/null
    sed -i -e "s/max_execution_time = [0-9]\{1,\}/max_execution_time = 500/" /etc/php/7.4/cli/php.ini 2>&1 1>/dev/null
    sed -i -e "s/allow_url_fopen = Off/allow_url_fopen = On/" /etc/php/7.4/cli/php.ini 2>&1 1>/dev/null
    sed -i -e "s/;max_input_vars = [0-9]\{1,\}/max_input_vars = 5000/" /etc/php/7.4/cli/php.ini 2>&1 1>/dev/null
    sed -i -e "s/max_input_time = [0-9]\{1,\}/max_input_time = 600/" /etc/php/7.4/cli/php.ini 2>&1 1>/dev/null
    # Based on these "minimum" values from Eramba    
    # Setting, Required Value
    # memory_limit, 2048M
    # post_max_size, 300M
    # file_uploads, On
    # upload_max_filesize, 300M
    # max_execution_time, 300
    # allow_url_fopen, On
    # max_input_vars, 3000
    # max_input_time, 600
    /usr/bin/logger 'configure_php() finished' -t 'erambaCE-2021-11-12';
}

configure_apache() {
    /usr/bin/logger 'configure_apache()' -t 'erambaCE-2021-11-12';
    # Change ROOTCA to point to correct cert when/if not using self signed cert.
    export ROOTCA=$HOSTNAME
    # Enable Apache modules required
    a2enmod rewrite ssl headers 2>&1 1>/dev/null;
    # TLS
    cat << __EOF__ > /etc/apache2/sites-available/eramba.conf;
    <VirtualHost *:80>
        ServerName $HOSTNAME
        RewriteEngine On
        RewriteCond %{REQUEST_URI} !^/\.well\-known/acme\-challenge/
        RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
    </VirtualHost>

<VirtualHost *:443>
    ServerName $HOSTNAME
    DocumentRoot /var/www/html/eramba_community/
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

            SSLEngine on
            SSLCertificateFile "/etc/apache2/certs/$HOSTNAME.crt"
            SSLCertificateKeyFile "/etc/apache2/certs/$HOSTNAME.key"
            SSLCertificateChainFile "/etc/apache2/certs/$ROOTCA.crt"

            # enable HTTP/2, if available
        Protocols h2 http/1.1

        # HTTP Strict Transport Security (mod_headers is required)
        Header always set Strict-Transport-Security "max-age=63072000"

        <Directory /var/www/html/eramba_community/>
                Options +Indexes
                AllowOverride All
                Options FollowSymLinks 
        Options -MultiViews
        allow from all
        deny from all
        </Directory>
</VirtualHost>

# modern configuration
SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2
SSLHonorCipherOrder     off
SSLSessionTickets       off

SSLUseStapling On
SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
__EOF__

    # Turn off detail Header information
    cat << __EOF__ >> /etc/apache2/apache2.conf;
ServerTokens Prod
ServerSignature Off
FileETag None
__EOF__

    # Enable Eramba site
    #Remove default apache/debian site
    rm /etc/apache2/sites-enabled/*.conf;
    # Link Eramba site == enable site
    ln /etc/apache2/sites-available/eramba.conf /etc/apache2/sites-enabled/;
    /usr/bin/logger 'configure_apache() finished' -t 'erambaCE-2021-11-12';
}

configure_eramba() {
    /usr/bin/logger 'configure_eramba()' -t 'erambaCE-2021-11-12';
    # Change "Upgrade to Enterprise notification" to EE
    #sed -i -e "s/Upgrade to enterprise version/EE/" /var/www/html/eramba_community/app/View/Layouts/default.ctp;
    # Eramba CRON - needs to run before Eramba health is ok - see run_cron()
    cat << __EOF__ >> /var/spool/cron/crontabs/root
# Eramba Maintenance Cron Jobs
@hourly su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job hourly" www-data
@daily su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job daily" www-data
@yearly su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job yearly" www-data
__EOF__
    sync;
    chmod 600 /var/spool/cron/crontabs/root 2>&1 1>/dev/null;
    chown root:root /var/spool/cron/crontabs/root 2>&1 1>/dev/null;
    /usr/bin/logger 'configure_eramba() finished' -t 'erambaCE-2021-11-12';
}

configure_permissions() {
    /usr/bin/logger 'configure_permissions()' -t 'erambaCE-2021-11-12';
    chown -R www-data:www-data /var/www/html/ 2>&1 1>/dev/null;
    /usr/bin/logger 'configure_permissions() finished' -t 'erambaCE-2021-11-12';
}

configure_iptables() {
    /usr/bin/logger 'configure_iptables() started' -t 'bSIEM Step2';
    echo -e "\e[32mconfigure_iptables()\e[0m";
    echo -e "\e[32m-Creating iptables rules file\e[0m";
    cat << __EOF__  >> /etc/network/iptables.rules
##
## Ruleset for Eramba Server
##
## IPTABLES Ruleset Author: Martin Boller 2021-11-11 v1

*filter
## Dropping anything not explicitly allowed
##
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:LOG_DROPS - [0:0]

## DROP IP fragments
-A INPUT -f -j LOG_DROPS
-A INPUT -m ttl --ttl-lt 4 -j LOG_DROPS

## DROP bad TCP/UDP combinations
-A INPUT -p tcp --dport 0 -j LOG_DROPS
-A INPUT -p udp --dport 0 -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL NONE -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL ALL -j LOG_DROPS

## Allow everything on loopback
-A INPUT -i lo -j ACCEPT

## SSH, DNS, WHOIS, DHCP ICMP - Add anything else here needed for ntp, monitoring, dhcp, icmp, updates, and ssh
##
## SSH
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
## DNS
-A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 853 -j ACCEPT
## HTTP(S)
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
## NTP
-A INPUT -p udp -m udp --dport 123 -j ACCEPT
-A OUTPUT -p udp -m udp --dport 123 -j ACCEPT
## DHCP
-A OUTPUT -p udp -m udp --dport 67 -j ACCEPT
## ICMP
-A OUTPUT -p icmp -j ACCEPT
-A INPUT -p icmp -j ACCEPT
## Already established sessions
-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

## Logging
-A OUTPUT -j LOG_DROPS
## get rid of broadcast noise
-A LOG_DROPS -d 255.255.255.255 -j DROP
# Drop Broadcast to internal networks
-A LOG_DROPS -m pkttype --pkt-type broadcast -d 192.168.0.0/16 -j DROP
-A LOG_DROPS -p ip -m limit --limit 60/sec -j LOG --log-prefix "iptables:" --log-level 7
-A LOG_DROPS -j DROP

## Commit everything
COMMIT
__EOF__

    # Configure separate file for iptables logging
    cat << __EOF__  >> /etc/rsyslog.d/30-iptables-syslog.conf
:msg,contains,"iptables:" /var/log/iptables.log
& stop
__EOF__
    sync 2>&1 1>/dev/null;
    systemctl restart rsyslog.service 2>&1 1>/dev/null;

    # Configure daily logrotation (forward this log to log mgmt)
    cat << __EOF__  >> /etc/logrotate.d/iptables
/var/log/iptables.log {
  rotate 2
  daily
  compress
  create 640 root root
  notifempty
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
__EOF__

# Apply iptables at boot
    echo -e "\e[36m-Script applying iptables rules\e[0m";
    cat << __EOF__  >> /etc/network/if-up.d/firewallrules
#! /bin/bash
iptables-restore < /etc/network/iptables.rules
exit 0
__EOF__
    sync 2>&1 1>/dev/null;
    ## make the script executable
    chmod +x /etc/network/if-up.d/firewallrules 2>&1 1>/dev/null;
    # Apply firewall rules
    #/etc/network/if-up.d/firewallrules;
    /usr/bin/logger 'configure_iptables() done' -t 'Firewall setup';
}

show_databases() {
    echo -e "\e[1;32m------------------------------\e[0m"
    echo -e "\e[1;32mShowing databases.....\e[0m"
    mysql -e "show databases;"
    echo -e "\e[1;32m------------------------------\e[0m"
    /usr/bin/logger ''Databases $(mysql -e "show databases;")'' -t 'erambaCE-2021-11-12';
}

run_cron() {
    /usr/bin/logger 'run_cron()' -t 'erambaCE-2021-11-12';
    # Prerun these cron jobs in order to get all greens in Eramba health
    su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job hourly" www-data 2>&1 1>/dev/null
    su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job yearly" www-data 2>&1 1>/dev/null
    # Daily will not run successfully until after first login as Admin/Admin and password changed
    #su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job daily" www-data
    echo -e "\e[1;32m--------------------------------------------------------------------------------------\e[0m"
    echo -e "\e[1;31m!! Daily will not run successfully until after first login as admin/admin and password changed !!\e[0m"
    echo -e "\e[1;31m!! Run the following command after you have logged in the first time\e[0m"
    echo -e 'su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job daily" www-data'
    echo -e "\e[1;31m!! Daily will not run successfully until after first login as admin/admin, see above !!\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------------------\e[0m"
    /usr/bin/logger 'run_cron() finished' -t 'erambaCE-2021-11-12';
}

create_htpasswd() {
    /usr/bin/logger 'create_htpasswd()' -t 'eramba';
    export HT_PASSWD="$(< /dev/urandom tr -dc A-Za-z0-9 | head -c 32)"
    mkdir -p /mnt/backup/ 2>&1 1>/dev/null;
    htpasswd -cb /etc/apache2/.htpasswd eramba $HT_PASSWD 2>&1 1>/dev/null;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    echo "Created password for Apache $HOSTNAME     eramba:$ht_passwd"  >> /mnt/backup/readme-users.txt;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    /usr/bin/logger 'create_htpasswd() finished' -t 'eramba';
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    /usr/bin/logger 'Installing Eramba.......' -t 'eramba';
     # install all required elements and generate certificates for webserver
    install_prerequisites;
    prepare_nix;
    generate_certificates;
    install_pdf_tools;
    install_apache;
    install_mariadb;
    install_php;
    install_eramba;
    # Configure components
    prepare_mariadb;
    configure_mariadb;
    configure_php;
    configure_apache;
    configure_eramba;
    configure_iptables;
    create_htpasswd;
    start_services;
    configure_permissions;
    
    run_cron;
    show_databases;
    check_services;
    /usr/bin/logger 'Eramba Installation complete' -t 'erambaCE-2021-11-12';
    echo -e;
    echo -e "\e[1;32mInstallation complete\e[0m";
}

main;

exit 0;

######################################################################################################################################
# Post install 
# 
# Under settings -> crontab change hostname to FQDN in the Eramba web console
# /var/www/html/eramba_community/app/Console/cake cron test
# /var/www/html/eramba_community/app/Console/cake system_health check   
#
# the hourly, daily, and monthly cron job
# su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job hourly" www-data
# su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job daily" www-data
# su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job yearly" www-data
#