# Eramba Community Edition Installation script

## Bash script automating the installation of Eramba Community Edition on Debian 11

## Vagrantfile and bootstrap.sh for use with Vagrant and Virtualbox

### Design principles:
  - Dedicated to Eramba, nothing else
  - Use the defaults where possible
  - Least access



### Known issues:
  - Currently using self signed cert, but the CSR is there so send that to Issuing CA instead
  - crontab not configured correctly, uses hostname only not fqdn - change in Eramba web console settings -> crontab for now
  - ~~Not tested with anything else than Debian 11 (Bullseye)~~

### Latest changes 
#### 2021-11-04 - Initial version
  Version 1.0
#### 2021-11-04 - Create certificates for Apache
  Version 1.5 - Now with cert  

