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
