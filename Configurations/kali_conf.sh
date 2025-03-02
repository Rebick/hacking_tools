#!/bin/bash
sed -i '/# enable command-not-found if installed/a \
if [ -f ~/.bash_aliases ]; then\n    . ~/.bash_aliases\nfi' ~/.zshrc

echo -e 'function apt-updater {\n    sudo apt update &&\n    sudo apt dist-upgrade -y &&\n    sudo apt autoremove -y &&\n    sudo apt autoclean\n}\n' >> ~/.bash_aliases
source ~/.bash_aliases

# Actualizar el sistema e instalar archivos básicos
# Instalar ufw (firewall) y fail2ban (protección contra ataques de fuerza bruta)
# Instalar sendmail para la funcionalidad de correo
apt-updater && sudo apt install -y kali-linux-headless terminator kali-desktop-xfce xorg xrdp ufw fail2ban sendmail-bin sendmail libpam-google-authenticator tomcat10

# Instalar paquetes para RDP
sudo systemctl enable xrdp --now

# Cambiar la contraseña del usuario kali
sudo passwd kali
# A prueba de:
# - Virus, trojan, worm, spyware
# - Backdoor
# - IP spoofing
# - Atacantes que cambian de IP
# - Botnet


sudo cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

sudo sed -i '/backend = %(sshd_backend)s/{n;s/enable = false/enable = true/}' /etc/fail2ban/jail.conf

sudo ufw allow 22 comment "Allow SSH"
sudo ufw allow 3389 comment "Allow RDP"
sudo ufw default deny incoming
sudo ufw logging medium

#Para excluir una IP
#sudo fail2ban-client set sshd unbanip 20.50.12.2

sudo service ufw start
sudo service fail2ban start
sudo ufw --force enable

sudo sed -i 's/#\?PasswordAuthentication\s\+no/PasswordAuthentication yes/' /etc/ssh/sshd_config

google-authenticator
#/y
#/y
#/y
#/y
# Agregar 'auth required pam_google_authenticator.so' al final de /etc/pam.d/sshd
echo "auth required pam_google_authenticator.so" | sudo tee -a /etc/pam.d/sshd > /dev/null

# autenticacion google para ssh
sudo sed -i 's/^KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
#autenticacion google rdp
echo "auth required pam_google_authenticator.so forward_pass" > /tmp/tempfile
echo "auth required pam_google_authenticator.so forward_pass" >>  /etc/pam.d/xrdp-sesman
echo "auth required pam_unix.o use_first_pass" >>  /etc/pam.d/xrdp-sesman

sudo systemctl restart xrdp
sudo systemctl restart ssh
exit 0
