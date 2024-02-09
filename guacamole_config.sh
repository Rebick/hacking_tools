## guacamole server
```
sudo apt update -y && sudo apt install tomcat10 tomcat10-admin tomcat10-common tomcat10-user
sudo apt install build-essential libcairo2-dev libjpeg62-turbo-dev libtool-bin libossp-uuid-dev libavcodec-dev libavutil-dev libswscale-dev freerdp2-dev libpango1.0-dev libssh2-1-dev libtelnet-dev libvncserver-dev libwebsockets-dev libpulse-dev libssl-dev libvorbis-dev libwebp-dev -y
git clone https://github.com/apache/guacamole-server.git
cd guacamole-server
autoreconf -fi
./configure --with-init-dir=/etc/init.d
make
sudo make install
sudo ldconfig
sudo systemctl enable guacd
sudo systemctl start guacd
```
#guacamole client
```
wget https://apache.org/dyn/closer.lua/guacamole/1.4.0/binary/guacamole-1.4.0.war?action=download
sudo mkdir /etc/guacamole
sudo cp guacamole-1.4.0.war?action=download /etc/guacamole/guacamole-1.4.0.war
sudo ln -s /etc/guacamole/guacamole.war /var/lib/tomcat10/webapps/guacamole.war
sudo mkdir /etc/guacamole/{extensions,lib}
sudo sh -c 'echo "GUACAMOLE_HOME=/etc/guacamole" >> /etc/default/tomcat10'
sudo ufw allow 8080
```

#Hasta este punto está listo, ahora instalaremos el doble factor de autenticacion
```
sudo apt install mariadb-server mariadb-client
sudo systemctl start mariadb
mysql_secure_installation
Enter
n
y
y
y
y
```
#Autenticarse a mariadb

```
mysql -u root -p
CREATE DATABASE guacamole_db;
CREATE USER 'guacamole_user'@'localhost' IDENTIFIED BY 'SuP3r$3cr3tPwDD';
GRANT SELECT,INSERT,UPDATE,DELETE ON guacamole_db.* TO 'guacamole_user'@'localhost';
FLUSH PRIVILEGES;
quit;
```
#Extension de guacamole
wget https://apache.org/dyn/closer.lua/guacamole/1.4.0/binary/guacamole-auth-jdbc-1.4.0.tar.gz?action=download
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
