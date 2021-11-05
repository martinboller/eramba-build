#! /bin/bash

#############################################################################
#                                                                           #
# Author:       Martin Boller                                               #
#                                                                           #
# Email:        martin                                                      #
# Last Update:  2021-11-04                                                  #
# Version:      1.00                                                        #
#                                                                           #
# Changes:      Initial Version (1.00)                                      #
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
    apt-get -y install adduser wget whois build-essential devscripts git unzip apt-transport-https ca-certificates curl gnupg2 software-properties-common dnsutils dirmngr --install-recommends;
    # Set correct locale
    locale-gen;
    update-locale;
    # Install for Eramba
    apt-get -y install php-curl php-ldap php-mbstring php-gd php-exif php-intl php-xml php-zip;
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
    apt-get -y install php php-mysql php libapache2-mod-php php-cli;
    # Required modules
    # PHP Common
    # PHP GD
    # PHP Intl
    # PHP Mbstring
    # PHP LDAP
    # PHP Curl
    # PHP MySQL
    # PHP XML
    # PHP Zip
    # PHP BZ2
    # PHP SimpleXML
    # PHP SQLite3
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
    cd /tmp/
    wget https://downloads.wkhtmltopdf.org/0.12/0.12.5/wkhtmltox_0.12.5-1.xenial_amd64.deb
    apt-get install ./wkhtmltox_0.12.5-1.xenial_amd64.deb
    /usr/bin/logger 'install_pdf_tools() finished' -t 'erambaCE-20211104';
}

prepare_nix() {
    /usr/bin/logger 'prepare_nix()' -t 'erambaCE-20211104';
    echo -e "\e[1;32mCreating Users, configuring sudoers, and setting locale\e[0m";
    # set desired locale
    localectl set-locale en_US.UTF-8;
    # Create gvm user
    /usr/sbin/useradd --system --create-home --home-dir /opt/gvm/ -c "gvm User" --shell /bin/bash gvm;
    mkdir /opt/gvm;
    chown gvm:gvm /opt/gvm;
    # Update the PATH environment variable
    echo "PATH=\$PATH:/opt/gvm/bin:/opt/gvm/sbin" > /etc/profile.d/gvm.sh;
    # Add GVM library path to /etc/ld.so.conf.d

    sh -c 'cat << EOF > /etc/ld.so.conf.d/greenbone.conf;
# Greenbone libraries
/opt/gvm/lib
/opt/gvm/include
EOF'

# sudoers.d to run openvas as root
    sh -c 'cat << EOF > /etc/sudoers.d/greenbone
gvm     ALL = NOPASSWD: /opt/gvm/sbin/gsad, /opt/gvm/sbin/gvmd, /opt/gvm/sbin/openvas

Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/gvm/sbin"
EOF'
    # It appears that GVMD sometimes delete /run/gvm so added a subfolder (/gse) to prevent this
    sh -c 'cat << EOF > /etc/tmpfiles.d/greenbone.conf
d /run/gvm 1775 gvm gvm
d /run/gvm/gse 1775 root root
d /run/ospd 1775 gvm gvm
d /run/ospd/gse 1775 root root
EOF'
    # start systemd-tmpfiles to create directories
    systemd-tmpfiles --create;
    /usr/bin/logger 'prepare_nix() finished' -t 'erambaCE-20211104';

}

install_eramba() {    
    /usr/bin/logger 'install_eramba()' -t 'erambaCE-20211104';
    echo -e "\e[1;32mPreparing Eramba Source files\e[0m";
    mkdir -p /var/www/html/;
    mkdir -p /tmp/eramba/;
    cd /tmp/eramba;
    wget https://downloadseramba.s3-eu-west-1.amazonaws.com/CommunityTGZ/latest.tgz
    sync;
    tar -xzf latest.tgz -C /var/www/;
    sync;
    /usr/bin/logger 'install_eramba finished' -t 'erambaCE-20211104';
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
    /usr/bin/logger 'start_services finished' -t 'erambaCE-20211104';
}

configure_mariadb() {
    /usr/bin/logger 'configure_mariadb' -t 'erambaCE-20211104';
#     sh -c 'cat << EOF > /etc/tmpfiles.d/redis.conf
# d /run/redis 0755 redis redis
# EOF'
#     # start systemd-tmpfiles to create directories
#     systemd-tmpfiles --create;
#     sh -c 'cat << EOF  > /etc/redis/redis.conf
# daemonize yes
# pidfile /run/redis/redis-server.pid
# port 0
# tcp-backlog 511
# unixsocket /run/redis/redis.sock
# unixsocketperm 766
# timeout 0
# tcp-keepalive 0
# loglevel notice
# syslog-enabled yes
# databases 4097
# stop-writes-on-bgsave-error yes
# rdbcompression yes
# rdbchecksum yes
# dbfilename dump.rdb
# dir /var/lib/redis
# slave-serve-stale-data yes
# slave-read-only yes
# repl-disable-tcp-nodelay no
# slave-priority 100
# maxclients 20000
# appendonly no
# appendfilename "appendonly.aof"
# appendfsync everysec
# no-appendfsync-on-rewrite no
# auto-aof-rewrite-percentage 100
# auto-aof-rewrite-min-size 64mb
# lua-time-limit 5000
# slowlog-log-slower-than 10000
# slowlog-max-len 128
# latency-monitor-threshold 0
# notify-keyspace-events ""
# hash-max-ziplist-entries 512
# hash-max-ziplist-value 64
# list-max-ziplist-entries 512
# list-max-ziplist-value 64
# set-max-intset-entries 512
# zset-max-ziplist-entries 128
# zset-max-ziplist-value 64
# hll-sparse-max-bytes 3000
# activerehashing yes
# client-output-buffer-limit normal 0 0 0
# client-output-buffer-limit slave 256mb 64mb 60
# client-output-buffer-limit pubsub 32mb 8mb 60
# hz 10
# aof-rewrite-incremental-fsync yes
# EOF'
#     # Redis requirements - overcommit memory and TCP backlog setting > 511
#     sysctl -w vm.overcommit_memory=1;
#     sysctl -w net.core.somaxconn=1024;
#     echo "vm.overcommit_memory=1" >> /etc/sysctl.d/60-gse-redis.conf;
#     echo "net.core.somaxconn=1024" >> /etc/sysctl.d/60-gse-redis.conf;
#     # Disable THP
#     echo never > /sys/kernel/mm/transparent_hugepage/enabled;
#     sh -c 'cat << EOF  > /etc/default/grub.d/99-transparent-huge-page.cfg
# # Turns off Transparent Huge Page functionality as required by redis
# GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT transparent_hugepage=never"
# EOF'
#     update-grub;
    sync;
    /usr/bin/logger 'configure_mariadb finished' -t 'erambaCE-20211104';
}

configure_php() {
    /usr/bin/logger 'configure_php()' -t 'erambaCE-20211104';
    sed -i -e "s/upload_max_filesize = [0-9]\{1,\}M/upload_max_filesize = 500M/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/memory_limit = [0-9]\{1,\}M/memory_limit = 2048M/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/post_max_size = [0-9]\{1,\}M/post_max_size = 500M/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/file_uploads = Off/post_max_size = On/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/max_execution_time = [0-9]\{1,\}/max_execution_time = 500/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/allow_url_fopen = Off/allow_url_fopen = On/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/;max_input_vars = [0-9]\{1,\}/max_input_vars = 5000/" /etc/php/7.4/apache2/php.ini
    sed -i -e "s/max_input_time = [0-9]\{1,\}/max_input_time = 600/" /etc/php/7.4/apache2/php.ini
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
    a2enmod rewrite;
    sh -c 'cat << EOF > /etc/apache2/sites-available/eramba.conf;
<VirtualHost *:80>
#	ServerName hostname.yourdomain.org
#	ServerAdmin webmaster@yourdomain.org
	DocumentRoot /var/www/html/eramba_community/
	ErrorLog \${APACHE_LOG_DIR}/eramba.org.error.log
	CustomLog \${APACHE_LOG_DIR}/eramba.org.access.log combined

        <Directory /var/www/html/eramba_community/>
                Options +Indexes
                AllowOverride All
                Options FollowSymLinks 
		Options -MultiViews
                allow from all
        </Directory>
</VirtualHost>
EOF'
    #configure Eramba site
    rm /etc/apache2/sites-enabled/*.conf;
    ln /etc/apache2/sites-available/eramba.conf /etc/apache2/sites-enabled/;
    /usr/bin/logger 'configure_apache() finished' -t 'erambaCE-20211104';
}

configure_eramba() {
    /usr/bin/logger 'configure_eramba()' -t 'erambaCE-20211104';
    /usr/bin/logger 'configure_eramba() finished' -t 'erambaCE-20211104';
}

configure_permissions() {
    /usr/bin/logger 'configure_permissions()' -t 'erambaCE-20211104';
    /usr/bin/logger '..Setting correct ownership of files for user gvm' -t 'erambaCE-20211104';
    # Once more to ensure that GVM owns all files in /opt/gvm
    chown -R gvm:gvm /opt/gvm/;
    # GSE log files
    chown -R gvm:gvm /var/log/gvm/;
    # Openvas feed
    chown -R gvm:gvm /var/lib/openvas;
    # GVM Feed
    chown -R gvm:gvm /var/lib/gvm;
    # OSPD Configuration file
    chown -R gvm:gvm /etc/ospd/;
    /usr/bin/logger 'configure_permissions() finished' -t 'erambaCE-20211104';
}

show_databases() {
    echo -e "\e[1;32mShowing databases.....\e[0m"
    mysql -e "show databases;"
    /usr/bin/logger ''Databases $(mysql -e "show databases;")'' -t 'erambaCE-20211104';
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    # install
    install_prerequisites;
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
    #configure_permissions;
    start_services;
    show_databases;
    /usr/bin/logger 'Installation complete' -t 'erambaCE-20211104';
    echo -e;
    echo -e "\e[1;32mInstallation complete\e[0m";
}

main;

exit 0;

######################################################################################################################################
# Post install 
# 
# 