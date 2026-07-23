# 1. Delete the manual override configuration folder
sudo rm -rf /etc/systemd/system/mariadb.service.d

# 2. Tell systemd to reload its unit files
sudo systemctl daemon-reload

ls -la /etc/mysql/conf.d/
ls -la /etc/mysql/mariadb.conf.d/

# Backup and clear out custom config snippets that might contain syntax errors
sudo mkdir -p /tmp/mariadb_bak_config
sudo mv /etc/mysql/conf.d/* /tmp/mariadb_bak_config/ 2>/dev/null
sudo mv /etc/mysql/mariadb.conf.d/* /tmp/mariadb_bak_config/ 2>/dev/null

# 1. Purge the target data directory
sudo rm -rf /var/lib/mysql/*

# 2. Force install-db using the package's default behavior
sudo mariadb-install-db --user=mysql


sudo mkdir -p /etc/mysql/conf.d/
sudo mkdir -p /etc/mysql/mariadb.conf.d/
sudo chmod 755 /etc/mysql/conf.d/ /etc/mysql/mariadb.conf.d/
# 1. Clear any broken data remnants
sudo rm -rf /var/lib/mysql/*

# 2. Re-initialize the master structural tables
sudo mariadb-install-db --user=mysql
# 1. Create the missing data directory
sudo mkdir -p /var/lib/mysql

# 2. Assign ownership to the mysql system user
sudo chown -R mysql:mysql /var/lib/mysql

# 3. Secure the directory permissions
sudo chmod 700 /var/lib/mysql

