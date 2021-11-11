#! /bin/bash

#############################################################################
#                                                                           #
# Author:       Martin Boller                                               #
#                                                                           #
# Email:        martin                                                      #
# Last Update:  2021-11-10                                                  #
# Version:      1.50                                                        #
#                                                                           #
# Changes:      Initial Version (1.00)                                      #
#               Some cron stuff (1.50)                                      #
#                                                                           #
# Info:                                                                     #
#                                                                           #
#                                                                           #
# Instruction:  Run this script as root on a fully updated                  #
#               Debian 10 (Buster) or Debian 11 (Bullseye)                  #
#                                                                           #
#############################################################################


install_prerequisites() {
    /usr/bin/logger 'install_prerequisites' -t 'erambaCE-20211104';
    echo -e "\e[1;32m--------------------------------------------\e[0m";
    echo -e "\e[1;32mInstalling Prerequisite packages\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    # OS Version
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
    /usr/bin/logger "Operating System: $OS Version: $VER" -t 'erambaCE-20211104';
    echo -e "\e[1;32mOperating System: $OS Version: $VER\e[0m";
  # Install prerequisites
    apt-get update;
    # Install some basic tools on a Debian net install
    /usr/bin/logger '..Install some basic tools on a Debian net install' -t 'erambaCE-20211104';
    #apt-get -y install --fix-policy;
    apt-get -y install adduser wget whois unzip apt-transport-https ca-certificates curl gnupg2 software-properties-common dnsutils dirmngr --install-recommends useradd;
    # Set correct locale
    locale-gen;
    update-locale;
    # Install other preferences and clean up APT
    /usr/bin/logger '....Install some preferences on Debian and clean up APT' -t 'erambaCE-20211104';
    apt-get -y install bash-completion;
    # Install SUDO
    apt-get -y install sudo;
    # A little apt 
    apt-get -y install --fix-missing;
    apt-get update;
    apt-get -y full-upgrade;
    apt-get -y autoremove --purge;
    apt-get -y autoclean;
    apt-get -y clean;
    # Python pip packages
    python3 -m pip install --upgrade pip
    /usr/bin/logger 'install_prerequisites finished' -t 'erambaCE-20211104';
}

install_apache() {
    /usr/bin/logger 'install_apache()' -t 'erambaCE-20211104';
    apt-get -y install apache2 apache2-utils;
    /usr/bin/logger 'install_apache() finished' -t 'erambaCE-20211104';
}

install_php() {
    /usr/bin/logger 'install_php()' -t 'erambaCE-20211104';
    apt-get -y install php php-mysql libapache2-mod-php php-cli php-curl php-ldap php-mbstring php-gd php-exif php-intl php-xml php-zip \
        php-bz2 php-sqlite3 php-common;
    /usr/bin/logger 'install_php() finished' -t 'erambaCE-20211104';
}

install_mariadb() {
    /usr/bin/logger 'install_mariadb()' -t 'erambaCE-20211104';
    apt-get -y install mariadb-server;
    /usr/bin/logger 'install_mariadb() finished' -t 'erambaCE-20211104';
}

configure_mariadb() {
    /usr/bin/logger 'configure_mariadb()' -t 'erambaCE-20211104';
    mysql_secure_installation;
    /usr/bin/logger 'configure_mariadb() finished' -t 'erambaCE-20211104';
}

install_pdf_tools() {
    /usr/bin/logger 'install_pdf_tools()' -t 'erambaCE-20211104';
    cd /tmp/;
    wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox_0.12.6-1.buster_amd64.deb -O ./wkhtmltox.deb
    apt-get -y install ./wkhtmltox.deb -f;
    /usr/bin/logger 'install_pdf_tools() finished' -t 'erambaCE-20211104';
}

install_eramba() {    
    /usr/bin/logger 'install_eramba()' -t 'erambaCE-20211104';
    echo -e "\e[1;32mPreparing Eramba Source files\e[0m";
    mkdir -p /var/www/html/;
    mkdir -p /tmp/eramba/;
    cd /tmp/eramba;
    wget https://downloadseramba.s3-eu-west-1.amazonaws.com/CommunityTGZ/latest.tgz
    sync;
    tar -xzf latest.tgz -C /var/www/html/;
    sync;
    /usr/bin/logger 'install_eramba finished' -t 'erambaCE-20211104';
}

generate_certificates() {
    /usr/bin/logger 'generate_certificates()' -t 'erambaCE-20211104';
    mkdir -p /etc/apache2/certs/;

    # organization name
    # (see also https://www.switch.ch/pki/participants/)
    export ORGNAME=eramba-community
    # the fully qualified server (or service) name, change if other servicename than hostname
    export FQDN=$HOSTNAME;

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
countryName         = DK
stateOrProvinceName = Denmark
localityName        = Aabenraa
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
    /usr/bin/logger 'generate_certificates() finished' -t 'erambaCE-20211104';
}

prepare_mariadb() {
    /usr/bin/logger 'prepare_mariadb()' -t 'erambaCE-20211104';
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
    /usr/bin/logger "Database $dbname successfully created" -t 'erambaCE-20211104';
    echo -e "\e[1;32mCreating user $dbusername .....\e[0m"
    mysql -e "CREATE USER ${dbusername}@localhost IDENTIFIED BY '${userpass}';"
    echo -e "\e[1;32mUser $dbusername successfully created\e[0m"
    /usr/bin/logger "User $dbusername successfully created" -t 'erambaCE-20211104';
    echo -e "\e[1;32mGranting ALL privileges on ${dbname} to ${dbusername}"
    mysql -e "GRANT ALL PRIVILEGES ON ${dbname}.* TO '${dbusername}'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    echo -e "\e[1;32mPrivileges successfully created for User: $dbusername on Database: $dbname\e[0m"
    /usr/bin/logger "Privileges granted to user $dbusername on database $dbname" -t 'erambaCE-20211104';
    echo -e "\e[1;32mCreating Eramba database schema on ${dbname}";
    for file in /var/www/html/eramba_community/app/Config/db_schema/*.sql; do cat "$file"; done | mysql eramba_data
    /usr/bin/logger "Schema created on database $dbname" -t 'erambaCE-20211104';
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    export default='$default'
    sh -c "cat << EOF > /var/www/html/eramba_community/app/Config/database.php;
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
EOF"
    /usr/bin/logger 'prepare_mariadb() finished' -t 'erambaCE-20211104';
}

start_services() {
    /usr/bin/logger 'start_services' -t 'erambaCE-20211104';
    # Load new/changed systemd-unitfiles
    systemctl daemon-reload;
    # Enable services
    systemctl enable apache2;
    systemctl enable mariadb;
    # Start GSE units
    systemctl restart mariadb;
    systemctl restart apache2;
    /usr/bin/logger 'start_services finished' -t 'erambaCE-20211104';
}

check_services() {
    /usr/bin/logger 'check_services' -t 'erambaCE-20211104';
    # Check status of critical services
    # Apache
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    echo -e "\e[1;32mChecking core daemons for Eramba......\e[0m";
    if systemctl is-active --quiet apache2.service;
        then
            echo -e "\e[1;32mapache webserver started successfully";
            /usr/bin/logger 'apache webserver started successfully' -t 'erambaCE-20211104';
        else
            echo -e "\e[1;31mapache webserver FAILED!\e[0m";
            /usr/bin/logger 'apache webserver FAILED' -t 'erambaCE-20211104';
    fi
    # mariadb.service
    if systemctl is-active --quiet mariadb.service;
        then
            echo -e "\e[1;32mmariadb.service started successfully";
            /usr/bin/logger 'mariadb.service started successfully' -t 'erambaCE-20211104';
        else
            echo -e "\e[1;31mmariadb.service FAILED!\e[0m";
            /usr/bin/logger "mariadb.service FAILED!" -t 'erambaCE-20211104';
    fi
    /usr/bin/logger 'check_services finished' -t 'erambaCE-20211104';
}

configure_mariadb() {
    /usr/bin/logger 'configure_mariadb' -t 'erambaCE-20211104';
     sh -c 'cat << EOF >> /etc/mysql/my.cnf 
[mysqld]
sql_mode="NO_ENGINE_SUBSTITUTION"
max_allowed_packet="128000000"
innodb_lock_wait_timeout="200"
EOF'
    /usr/bin/logger 'configure_mariadb finished' -t 'erambaCE-20211104';
}

configure_php() {
    /usr/bin/logger 'configure_php()' -t 'erambaCE-20211104';
    # Apache
    sed -i -e "s/upload_max_filesize = [0-9]\{1,\}M/upload_max_filesize = 50M/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/memory_limit = [0-9]\{1,\}M/memory_limit = 2048M/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/post_max_size = [0-9]\{1,\}M/post_max_size = 500M/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/file_uploads = Off/post_max_size = On/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/max_execution_time = [0-9]\{1,\}/max_execution_time = 500/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/allow_url_fopen = Off/allow_url_fopen = On/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/;max_input_vars = [0-9]\{1,\}/max_input_vars = 5000/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/max_input_time = [0-9]\{1,\}/max_input_time = 600/" /etc/php/7.4/apache2/php.ini
    # CLI must be same values
    sed -i -e "s/upload_max_filesize = [0-9]\{1,\}M/upload_max_filesize = 50M/" /etc/php/7.4/cli/php.ini
    sed -i -e "s/memory_limit = -[0-9]\{1,\}/memory_limit = 2048M/" /etc/php/7.4/cli/php.ini
    sed -i -e "s/post_max_size = [0-9]\{1,\}M/post_max_size = 500M/" /etc/php/7.4/cli/php.ini
    sed -i -e "s/file_uploads = Off/post_max_size = On/" /etc/php/7.4/cli/php.ini
    sed -i -e "s/max_execution_time = [0-9]\{1,\}/max_execution_time = 500/" /etc/php/7.4/cli/php.ini
    sed -i -e "s/allow_url_fopen = Off/allow_url_fopen = On/" /etc/php/7.4/cli/php.ini
    sed -i -e "s/;max_input_vars = [0-9]\{1,\}/max_input_vars = 5000/" /etc/php/7.4/cli/php.ini
    sed -i -e "s/max_input_time = [0-9]\{1,\}/max_input_time = 600/" /etc/php/7.4/cli/php.ini
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
    /usr/bin/logger 'configure_php() finished' -t 'erambaCE-20211104';
}

configure_apache() {
    /usr/bin/logger 'configure_apache()' -t 'erambaCE-20211104';
    a2enmod rewrite ssl;
    # plain http
#     sh -c "cat << EOF > /etc/apache2/sites-available/eramba.conf;
# <VirtualHost *:80>
# 	ServerName $HOSTNAME.$DOMAINNAME
# #	ServerAdmin webmaster@yourdomain.org
# 	DocumentRoot /var/www/html/eramba_community/
# 	ErrorLog \${APACHE_LOG_DIR}/eramba.org.error.log
# 	CustomLog \${APACHE_LOG_DIR}/eramba.org.access.log combined

#         <Directory /var/www/html/eramba_community/>
#                 Options +Indexes
#                 AllowOverride All
#                 Options FollowSymLinks 
# 		Options -MultiViews
#                 allow from all
#         </Directory>
# </VirtualHost>
# EOF"

    # TLS
    sh -c "cat << EOF > /etc/apache2/sites-available/eramba.conf;
    <VirtualHost *:80>
    ServerName $HOSTNAME
    #ServerAdmin 
    DocumentRoot /var/www/html/eramba_community/
            Redirect  /  https://$HOSTNAME
</VirtualHost>

<VirtualHost *:443>
    ServerName $HOSTNAME
    DocumentRoot /var/www/html/eramba_community/
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

               SSLEngine on
               SSLCertificateFile "/etc/apache2/certs/$HOSTNAME.crt"
               SSLCertificateKeyFile "/etc/apache2/certs/$HOSTNAME.key"
               #SSLCertificateChainFile /path/to/rootca.crt

        <Directory /var/www/html/eramba_community/>
                Options +Indexes
                AllowOverride All
                Options FollowSymLinks 
        Options -MultiViews
        allow from all
        deny from all
        </Directory>
</VirtualHost>
EOF"
    # Enable Eramba site
    #Remove default apache/debian site
    rm /etc/apache2/sites-enabled/*.conf;
    # Link Eramba site == enable site
    ln /etc/apache2/sites-available/eramba.conf /etc/apache2/sites-enabled/;
    /usr/bin/logger 'configure_apache() finished' -t 'erambaCE-20211104';
}

configure_eramba() {
    /usr/bin/logger 'configure_eramba()' -t 'erambaCE-20211104';
    # Change "Upgrade to Enterprise notification" to EE
    #sed -i -e "s/Upgrade to enterprise version/EE/" /var/www/html/eramba_community/app/View/Layouts/default.ctp;
    /usr/sbin/useradd --system --create-home -c "Eramba User" --shell /bin/bash eramba;
    # Eramba CRON - needs to run before Eramba health is ok - see run_cron()
    sh -c cat << __EOF__ >> /var/spool/cron/crontabs/root
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command

# Eramba Maintenance Cron Jobs
@hourly su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job hourly" www-data
@daily su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job daily" www-data
@yearly su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job yearly" www-data
__EOF__
    sync;
    chmod 600 /var/spool/cron/crontabs/root;
    chown root:root /var/spool/cron/crontabs/root;
    # Configure MOTD
    BUILDDATE=$(date +%Y-%m-%d)
    sh -c cat << __EOF__ >> /etc/motd
           
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
            bsecure.dk

__EOF__
    # do not show motd twice
    sed -ie 's/session    optional     pam_motd.so  motd=\/etc\/motd/#session    optional     pam_motd.so  motd=\/etc\/motd/' /etc/pam.d/sshd
    /usr/bin/logger 'configure_eramba() finished' -t 'erambaCE-20211104';
}

configure_permissions() {
    /usr/bin/logger 'configure_permissions()' -t 'erambaCE-20211104';
    chown -R www-data:www-data /var/www/html/;
    /usr/bin/logger 'configure_permissions() finished' -t 'erambaCE-20211104';
}

show_databases() {
    echo -e "\e[1;32mShowing databases.....\e[0m"
    mysql -e "show databases;"
    /usr/bin/logger ''Databases $(mysql -e "show databases;")'' -t 'erambaCE-20211104';
}

run_cron() {
    /usr/bin/logger 'run_cron()' -t 'erambaCE-20211104';
    # Prerun these cron jobs in order to get all greens in Eramba health
    su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job hourly" www-data
    su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job yearly" www-data
    # Daily will not run successfully until after first login as Admin/Admin and password changed
    su -s /bin/bash -c "/var/www/html/eramba_community/app/Console/cake cron job daily" www-data
    /usr/bin/logger 'run_cron() finished' -t 'erambaCE-20211104';
}

create_htpasswd() {
    /usr/bin/logger 'create_htpasswd()' -t 'eramba';
    export HT_PASSWD="$(< /dev/urandom tr -dc A-Za-z0-9 | head -c 32)"
    mkdir -p /mnt/backup/;
    htpasswd -cb /etc/apache2/.htpasswd eramba $HT_PASSWD;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    echo "Created password for Apache $HOSTNAME     eramba:$ht_passwd"  >> /mnt/backup/readme-users.txt;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    /usr/bin/logger 'create_htpasswd() finished' -t 'eramba';
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    # install all required elements and generate certificates for webserver
    install_prerequisites;
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
    create_htpasswd;
    #configure_permissions;
    start_services;
    configure_permissions;
    run_cron;
    show_databases;
    check_services;
    /usr/bin/logger 'Installation complete' -t 'erambaCE-20211104';
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