sudo docker pull guacamole/guacamole
docker run --name some-guacamole --link some-guacd:guacd \
    --link some-mysql:mysql         \
    -e MYSQL_DATABASE=guacamole_db  \
    -e MYSQL_USER=guacamole_user    \
    -e MYSQL_PASSWORD=goro1703! \
    -d -p 8080:8080 guacamole/guacamole
#Autenticarse a mariadb

#Extension de guacamole
https://dlcdn.apache.org/guacamole/1.5.4/binary/guacamole-auth-jdbc-1.5.4.tar.gz
mv guacamole-auth-jdbc-1.4.0.tar.gz?action=download guacamole-auth-jdbc-1.4.0.tar.gz
tar -xzf guacamole-auth-jdbc-1.4.0.tar.gz
cat guacamole-auth-jdbc-1.4.0/mysql/schema/*.sql | mysql -u root -p guacamole_db
sudo cp guacamole-auth-jdbc-1.4.0/mysql/guacamole-auth-jdbc-mysql-1.4.0.jar /etc/guacamole/extensions/
wget https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-8.0.13.tar.gz
tar -xzf mysql-connector-java-8.0.13.tar.gz
sudo cp mysql-connector-java-8.0.13/mysql-connector-java-8.0.13.jar /etc/guacamole/lib/
mysql_tzinfo_to_sql /usr/share/zoneinfo | mysql -u root -p mysql
sudo sh -c 'echo "default_time_zone='Europe/Brussels'" >> /etc/mysql/mariadb.conf.d/50-server.cnf'
sudo systemctl restart mariadb.service
sudo tee -a /etc/guacamole/guacamole.properties >/dev/null <<EOL
#Hostname and Guacamole server port
guacd-hostname: localhost
Guacd-port: 4822

#MySQL properties
mysql-hostname: localhost
mysql-port: 3306
mysql-database: guacamole_db
mysql-username: guacamole_user
mysql-password: SuP3r\$3cr3tPwDD

totp-issuer: Google-authenticator
EOL

sudo tee -a /etc/ssh/sshd_config >/dev/null <<EOL
  PubkeyAuthentication yes
  PubkeyAcceptedKeyTypes=+ssh-rsa
EOL

sudo systemctl restart sshd

#Optimizacion de Guacamole MFA GoogleAuth
wget https://apache.org/dyn/closer.lua/guacamole/1.4.0/binary/guacamole-auth-totp-1..4.0.tar.gz?action=download
mv guacamole-auth-totp-1..4.0.tar.gz?action=download guacamole-auth-totp-1..4.0.tar.gz
tar -xvzf guacamole-auth-totp-1.4.0.tar.gz
sudo cp guacamole-auth-totp-1.4.0/guacamole-auth-totp-1.4.0.jar /etc/guacamole/extensions/
sudo systemctl restart tomcat10.service

#Reverse Proxy Apache
sudo apt install apache2 -y
sudo a2enmod rewrite
sudo a2enmod proxy_http
sudo a2enmod proxy_wstunnel
echo '<VirtualHost *:80>
ServerName kali.rd-services.be
ProxyPass / http://127.0.0.1:8080/guacamole/ flushpackets=on
ProxyPassReverse / http://127.0.0.1:8080/guacamole
ProxyPassReverseCookiePath /guacamole /
<Location /websocket-tunnel>
  Order allow,deny
  Allow from all
  ProxyPass ws://127.0.0.1:8080/guacamole/websocket-tunnel
  ProxyPassReverse ws://127.0.0.1:8080/guacamole/websocket-tunnel
</Location>
SetEnvIf Request_URI "^/tunnel" dontlog
CustomLog /var/log/apache2/guac.log common env=!dontlog
</VirtualHost>' | sudo tee /etc/apache2/sites-enabled/000-default.conf >/dev/null

sudo systemctl restart apache2
sudo ufw allow 80
