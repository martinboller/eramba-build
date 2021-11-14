#! /bin/bash

#####################################################################
#                                                                   #
# Author:       Martin Boller                                       #
#                                                                   #
# Email:        martin                                              #
# Last Update:  2021-11-10                                          #
# Version:      1.00                                                #
#                                                                   #
# Changes:      First version for Eramba (1.00)                     #
#                                                                   #
#                                                                   #
#####################################################################

configure_locale() {
  echo -e "\e[32mconfigure_locale()\e[0m";
  echo -e "\e[36m-Configure locale (default:C.UTF-8)\e[0m";
  export DEBIAN_FRONTEND=noninteractive;
  sudo sh -c "cat << EOF  > /etc/default/locale
# /etc/default/locale
LANG=C.UTF-8
LANGUAGE=C.UTF-8
LC_ALL=C.UTF-8
EOF";
  update-locale;
  /usr/bin/logger 'configure_locale()' -t 'eramba';
}

configure_timezone() {
  echo -e "\e[32mconfigure_timezone()\e[0m";
  echo -e "\e[36m-Set timezone to Etc/UTC\e[0m";
  export DEBIAN_FRONTEND=noninteractive;
  sudo rm /etc/localtime;
  sudo sh -c "echo 'Etc/UTC' > /etc/timezone";
  sudo dpkg-reconfigure -f noninteractive tzdata;
  /usr/bin/logger 'configure_timezone()' -t 'eramba';
}

apt_install_prerequisites() {
    # Install prerequisites and useful tools
    export DEBIAN_FRONTEND=noninteractive;
    apt-get -y remove postfix*;
        sudo sync \
        && sudo apt-get update \
        && sudo apt-get -y full-upgrade \
        && sudo apt-get -y --purge autoremove \
        && sudo apt-get autoclean \
        && sudo sync;
        /usr/bin/logger 'install_updates()' -t 'eramba';
    sed -i '/dns-nameserver/d' /etc/network/interfaces;
    ifdown eth0; ifup eth0;
    # Remove memcached on vagrant box
    apt-get -y purge memcached;
    # copy relevant scripts
    /bin/cp /tmp/configfiles/Servers/*.sh /root/;
    /bin/cp /tmp/configfiles/Servers/*.cfg /root/;
    chmod +x /root/*.sh;
    /usr/bin/logger 'apt_install_prerequisites()' -t 'eramba';
}

install_ssh_keys() {
    # Echo add SSH public key for root logon
    export DEBIAN_FRONTEND=noninteractive;
    mkdir /root/.ssh;
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIHJYsxpawSLfmIAZTPWdWe2xLAH758JjNs5/Z2pPWYm" | sudo tee -a /root/.ssh/authorized_keys;
    sudo chmod 700 /root/.ssh;
    sudo chmod 600 /root/.ssh/authorized_keys;
    /usr/bin/logger 'install_ssh_keys()' -t 'eramba';
}

create_htpasswd() {
    /usr/bin/logger 'create_htpasswd() finished' -t 'eramba';
    export ht_passwd="$(< /dev/urandom tr -dc A-Za-z0-9 | head -c 32)"
    mkdir -p /mnt/backup/;
    htpasswd -cb /etc/nginx/.htpasswd  $HT_PASSWD;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    echo "Created password for Apache $HOSTNAME alerta:$ht_passwd"  >> /mnt/backup/readme-users.txt;
    echo "-------------------------------------------------------------------"  >> /mnt/backup/readme-users.txt;
    /usr/bin/logger 'create_htpasswd() finished' -t 'eramba';
    systemctl restart nginx.service;
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    export DOMAINNAME=bollers.dk;
    # Core elements, always installs
    /usr/bin/logger '!!!!! Main routine starting' -t 'eramba';
    hostnamectl set-hostname $HOSTNAME.$DOMAINNAME;
    # Do not forget to add your own public SSH Key(s) instead of dummy in install_ssh_keys()
    install_ssh_keys;
    configure_timezone;
    apt_install_prerequisites;
    configure_locale;
    configure_timezone;

    # copy relevant scripts
    /bin/cp /tmp/configfiles/* /root/;
    chmod +x /root/*.sh;
    apt-get -y install --fix-policy;
    /usr/bin/logger 'installation finished (Main routine finished)' -t 'eramba'; 
    su root -c '/root/install-eramba.sh';
}

main;

exit 0
