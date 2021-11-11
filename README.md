# Eramba Community Edition Installation script

## Bash script automating the installation of Eramba Community Edition on Debian 11

## Vagrantfile and bootstrap.sh for use with Vagrant and Virtualbox

### Design principles:
  - Dedicated to Eramba, nothing else
  - Use the defaults where possible
  - Least access



### Known issues:
  - Currently using self signed cert, but the CSR is there so send that to Issuing CA instead
  - Daily Cron job cannot run before first login with admin/admin and password changed.
  - ~~Not tested with anything else than Debian 11 (Bullseye)~~

### Latest changes 
#### 2021-11-04 - Initial version
  Version 1.00
#### 2021-11-07 - Create certificates for Apache
  Version 1.50 - Now with cert and cron adjusted 
