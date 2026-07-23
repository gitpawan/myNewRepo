# 1. Uninstall the server and purge its persistent configuration files
sudo apt purge -y mariadb-server mariadb-client mariadb-common

# 2. Obliterate any remnant database files and local configuration tweaks
sudo rm -rf /var/lib/mysql /etc/mysql /etc/my.cnf /var/log/mysql

# 1. Uninstall the server and purge its persistent configuration files
sudo apt purge -y mariadb-server mariadb-client mariadb-common

# 2. Obliterate any remnant database files and local configuration tweaks
sudo rm -rf /var/lib/mysql /etc/mysql /etc/my.cnf /var/log/mysql

# 1. Resynchronize your package indexes
sudo apt update

# 2. Install a fresh instance (this automatically triggers a native, empty db generation)
sudo apt install -y mariadb-server



# 1. Install AppArmor management tools
sudo apt install -y apparmor-utils

# 2. Put MariaDB into permissive "complain" mode
sudo aa-complain /usr/sbin/mariadbd

# 3. Fire up the database engine
sudo systemctl restart mariadb






# 1. Stop the database service safely
sudo systemctl stop mariadb

# 2. Clear out InnoDB transaction logs and tablespace boundaries
sudo rm -f /var/lib/mysql/ib_logfile*
sudo rm -f /var/lib/mysql/ibdata1
sudo rm -f /var/lib/mysql/aria_log*

sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf
# Remove or comment out these if found:
skip-innodb
innodb=OFF
innodb_buffer_pool_size = 32M

# 1. Clear out the directory fully one last time
sudo rm -rf /var/lib/mysql/*



#  Rebuilt the Missing System Configuration Folders
sudo mkdir -p /etc/mysql/conf.d/
sudo mkdir -p /etc/mysql/mariadb.conf.d/
sudo chmod 755 /etc/mysql/conf.d/ /etc/mysql/mariadb.conf.d/
# Recreated the Core Storage Directory & Set Permissions
sudo mkdir -p /var/lib/mysql
sudo chown -R mysql:mysql /var/lib/mysql
sudo chmod 700 /var/lib/mysql
#  Initialized the Missing Master System Databases
sudo mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
# Cleared System Blocks & Fired Up the Service
sudo rm -f /run/mysqld/mysqld.sock
sudo systemctl start mariadb
