#!/bin/bash

# Actualizar el sistema e instalar archivos básicos
sudo apt update && sudo apt install -y kali-linux-headless

# Instalar paquetes para RDP
sudo apt-get install -y kali-desktop-xfce xorg xrdp
sudo systemctl enable xrdp --now

# Cambiar la contraseña del usuario kali
sudo passwd kali
# A prueba de:
# - Virus, trojan, worm, spyware
# - Backdoor
# - IP spoofing
# - Atacantes que cambian de IP
# - Botnet

# Instalar ufw (firewall) y fail2ban (protección contra ataques de fuerza bruta)
sudo apt install -y ufw fail2ban

# Instalar sendmail para la funcionalidad de correo
sudo apt install -y sendmail-bin sendmail

sudo cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.conf.bak
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.bak

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

sudo apt install libpam-google-authenticator
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
sed '2 {e cat /tmp/tempfile' -i /etc/pam.d/xrdp-sesman

sudo systemctl restart xrdp
sudo systemctl restart sshd
exit 0
