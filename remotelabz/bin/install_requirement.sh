#!/bin/bash

apt-get update
apt-get -y upgrade
add-apt-repository -y ppa:ondrej/php # PPRI0603 : Ajout pour l'installation de PHP8.1
apt install -y fail2ban exim4 apache2 curl gnupg zip unzip ntp openvpn libapache2-mod-php8.1 # PPRI0603 : changement de version des modules PHP pour passer en PHP8.1
apt install -y php8.1 php8.1-bcmath php8.1-curl php8.1-gd php8.1-intl php8.1-mbstring php8.1-mysql php8.1-xml php8.1-zip # PPRI0603 : changement version des modules PHP pour passer en PHP8.1
apt-get update # PPRI0603 : Ajout
phpenmod -v 8.1 dom # PPRI0603 : Ajout
update-alternatives --set php /usr/bin/php8.1 # PPRI0603 : Ajout des 3 lignes suivantes pour forcer l'utilisation de php8.1
update-alternatives --set phar /usr/bin/phar8.1
update-alternatives --set phar.phar /usr/bin/phar.phar8.1
systemctl restart apache2
php -r "copy('https://getcomposer.org/download/2.8.6/composer.phar', 'composer.phar');" # PPRI0603 : passage de la version de composer 2.2.6 à 2.8.6
cp composer.phar /usr/local/bin/composer
chmod a+x /usr/local/bin/composer
curl -sL https://deb.nodesource.com/setup_18.x | sudo -E bash - # PPRI0603 : Passage de nodejs 14 vers nodejs 16
apt-get install -y nodejs
npm install -g yarn
npm install -g configurable-http-proxy
apt-get install -y mysql-server
systemctl restart mysql
cat > mysql_secure_sql.sql << EOF
ALTER USER IF EXISTS 'root'@'localhost' IDENTIFIED BY 'RemoteLabz-2022$';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
CREATE USER IF NOT EXISTS 'user'@'localhost' IDENTIFIED WITH mysql_native_password BY 'Mysql-Pa33wrd$';
CREATE DATABASE IF NOT EXISTS remotelabz;
GRANT ALL ON remotelabz.* TO 'user'@'localhost';
FLUSH PRIVILEGES;
EOF

mysql -sfu root < mysql_secure_sql.sql
rm ./mysql_secure_sql.sql

echo "The MySQL is configured with user \"user\" and the password \"Mysql-Pa33wrd$\""
apt-get install -y rabbitmq-server php8.1-amqp # PPRI0603 : Modification du module pour l'adapter à PHP 8.1
systemctl restart rabbitmq-server
if ! rabbitmqctl list_users | grep -q 'remotelabz-amqp'; then
    rabbitmqctl add_user 'remotelabz-amqp' 'password-amqp'
fi
rabbitmqctl set_permissions -p '/' 'remotelabz-amqp' '.*' '.*' '.*'
service rabbitmq-server restart
rabbitmqctl set_user_tags remotelabz-amqp administrator

rabbitmq-plugins enable rabbitmq_management

#To test if the connexion to the RabbitMQ works fine
#rabbitmqctl authenticate_user 'remotelabz-amqp' "password-amqp"

cd ~
wget -q https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz
tar -xzf EasyRSA-3.0.8.tgz
ln -s EasyRSA-3.0.8 EasyRSA
cd EasyRSA

cat > vars << EOF
set_var EASYRSA_BATCH           "yes"
set_var EASYRSA_REQ_CN         "RemoteLabz-VPNServer-CA"
set_var EASYRSA_REQ_COUNTRY    "FR"
set_var EASYRSA_REQ_PROVINCE   "Grand-Est"
set_var EASYRSA_REQ_CITY       "Reims"
set_var EASYRSA_REQ_ORG        "RemoteLabz"
set_var EASYRSA_REQ_EMAIL      "contact@remotelabz.com"
set_var EASYRSA_REQ_OU         "RemoteLabz-VPNServer"
set_var EASYRSA_ALGO           "ec"
set_var EASYRSA_DIGEST         "sha512"
set_var EASYRSA_CURVE          secp384r1
#5 ans de validité pour le CA
set_var EASYRSA_CA_EXPIRE      1825
#5 ans de validité pour les certificats
set_var EASYRSA_CERT_EXPIRE    1825
EOF

sed -i "s/RANDFILE/#RANDFILE/g" openssl-easyrsa.cnf

./easyrsa init-pki
echo "🔥 In the documentation, the password used to secure the CA certificate is 'R3mot3!abz-0penVPN-CA2020'"
echo "You can use the same password for the next question"
echo "This password have to be added in you .env file. It is used to sign all users VPN certificate"
./easyrsa build-ca

cp ./vars ./vars-ca

sed -i "s/RemoteLabz-VPNServer-CA/RemoteLabz-VPNServer/g" vars

echo "Generation of the client certificate"
./easyrsa gen-req RemoteLabz-VPNServer nopass
echo "You have to type your CA password use before (R3mot3!abz-0penVPN-CA2020)"
./easyrsa sign-req server RemoteLabz-VPNServer

echo "Copy the certificate file to your openvpn directory"
cp pki/issued/RemoteLabz-VPNServer.crt /etc/openvpn/server
cp pki/private/RemoteLabz-VPNServer.key /etc/openvpn/server
cp pki/ca.crt /etc/openvpn/server
cp pki/private/ca.key /etc/openvpn/server


openvpn --genkey --secret ta.key
cp ta.key /etc/openvpn/server
openssl dhparam -out dh2048.pem 2048
mv dh2048.pem /etc/openvpn/server
chown www-data: /etc/openvpn/server -R

cat > /etc/openvpn/server/server.conf << EOF
port 1194
proto udp
dev tun
ca ca.crt
cert RemoteLabz-VPNServer.crt
key RemoteLabz-VPNServer.key
dh dh2048.pem
cipher AES-256-GCM
tls-auth ta.key 0
server 10.8.0.0 255.255.255.0
keepalive 10 120
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log /var/log/openvpn/openvpn.log
verb 1
mute 20
explicit-exit-notify 1
duplicate-cn
push "route 10.11.0.0 255.255.0.0"
script-security 2
client-connect /etc/openvpn/scripts/client-connect.sh
client-disconnect /etc/openvpn/scripts/client-disconnect.sh
EOF

mkdir /etc/openvpn/scripts

cat > /etc/openvpn/scripts/add-client.sh << EOF
#!/bin/bash

CLIENT_NAME="$1"
MAPPING_FILE="/etc/openvpn/client-mappings.json"
BASE_SUBNET="10.11.0.0"
NETMASK_BITS=26
TOTAL_ADDRESSES=64

if [ -z "$CLIENT_NAME" ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

mkdir -p "$(dirname "$MAPPING_FILE")"
touch "$MAPPING_FILE"
[ ! -s "$MAPPING_FILE" ] && echo "{}" > "$MAPPING_FILE"

last_ip=$(jq -r '.[].subnet' "$MAPPING_FILE" | tail -n 1)
if [ -z "$last_ip" ]; then
    next_ip="$BASE_SUBNET"
else
    IFS=. read -r o1 o2 o3 o4 <<< "${last_ip%%/*}"
    total_ip=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 + TOTAL_ADDRESSES ))
    next_ip="$(( (total_ip >> 24) & 255 )).$(( (total_ip >> 16) & 255 )).$(( (total_ip >> 8) & 255 )).$(( total_ip & 255 ))"
fi

jq --arg client "$CLIENT_NAME" --arg subnet "$next_ip/$NETMASK_BITS" '. + {($client): { "subnet": $subnet }}' "$MAPPING_FILE" > "$MAPPING_FILE.tmp" && mv "$MAPPING_FILE.tmp" "$MAPPING_FILE"

echo "✅ Client '$CLIENT_NAME' ajouté avec le sous-réseau $next_ip/$NETMASK_BITS"
EOF

cat > /etc/openvpn/scripts/client-connect.sh << EOF
#!/bin/bash

CLIENT_NAME="$common_name"
MAPPING_FILE="/etc/openvpn/client-mappings.json"

if [ -z "$CLIENT_NAME" ]; then
    echo "Erreur : common_name non défini"
    exit 1
fi

SUBNET=$(jq -r --arg client "$CLIENT_NAME" '.[$client].subnet' "$MAPPING_FILE")

if [ "$SUBNET" == "null" ] || [ -z "$SUBNET" ]; then
    echo "Ajout automatique du client $CLIENT_NAME"
    /etc/openvpn/scripts/add-client.sh "$CLIENT_NAME"
    SUBNET=$(jq -r --arg client "$CLIENT_NAME" '.[$client].subnet' "$MAPPING_FILE")
fi

# Appliquer la règle iptables
iptables -A FORWARD -s "$ifconfig_pool_remote_ip" ! -d "$SUBNET" -j DROP
echo "🔒 Règle iptables appliquée pour $CLIENT_NAME : FORWARD -s $ifconfig_pool_remote_ip ! -d $SUBNET -j DROP"
EOF

cat > /etc/openvpn/scripts/client-disconnect.sh << EOF
#!/bin/bash

CLIENT_NAME="$common_name"
MAPPING_FILE="/etc/openvpn/client-mappings.json"

SUBNET=$(jq -r --arg client "$CLIENT_NAME" '.[$client].subnet' "$MAPPING_FILE")
iptables -D FORWARD -s "$ifconfig_pool_remote_ip" ! -d "$SUBNET" -j DROP
echo "♻️ Règle iptables supprimée pour $CLIENT_NAME"
EOF

cat > /etc/openvpn/scripts/list-client.sh << EOF
#!/bin/bash

MAPPING_FILE="/etc/openvpn/client-mappings.json"

if [ ! -f "$MAPPING_FILE" ]; then
    echo "Aucun mapping trouvé. Fichier introuvable : $MAPPING_FILE"
    exit 1
fi

echo "Liste des clients VPN et leurs sous-réseaux alloués :"
echo "------------------------------------------------------"

jq -r 'to_entries[] | "\(.key): \(.value)"' "$MAPPING_FILE"
EOF

apt install jq
chmod +x /etc/openvpn/scripts/*.sh
touch /etc/openvpn/client-mappings.json
chmod 600 /etc/openvpn/client-mappings.json


chown :www-data /etc/openvpn/client
chmod g+w /etc/openvpn/client

systemctl enable openvpn-server@server
service openvpn-server@server start

sysctl -w net.ipv4.ip_forward=1
sed -i 's/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/g' /etc/sysctl.conf
sed -i 's/#net.ipv4.ip_forward =/net.ipv4.ip_forward =/g' /etc/sysctl.conf

# To avoid error message "Too many opened files" and containers don't stop
sysctl -n -w fs.inotify.max_user_instances=512
sysctl -n -w fs.inotify.max_user_watches=16384
echo "fs.inotify.max_user_watches=16384" >> /etc/sysctl.conf
echo "fs.inotify.max_user_instances=512" >> /etc/sysctl.conf

echo "=== Installation de Docker ==="

# Installer Docker et outils nécessaires
apt-get update
apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    unzip \
    wget \
    sed

# Ajouter la clé GPG officielle de Docker
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Ajouter le dépôt Docker
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
  $(lsb_release -cs) stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

# Installer Docker Engine
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Activer et démarrer le service Docker
systemctl enable docker
systemctl start docker

echo "=== Docker installé avec succès ==="

# Vérifier que docker-compose est accessible via le plugin
if ! docker compose version &>/dev/null; then
  echo "docker-compose (plugin) n’est pas correctement installé."
  exit 1
fi

# Télécharger l'exemple officiel de LibreNMS Docker Compose
mkdir -p ~/librenms
cd ~/librenms || exit 1

wget https://github.com/librenms/docker/archive/refs/heads/master.zip
unzip master.zip
cd docker-master/examples/compose || exit 1

# Modifier le port de librenms de 8000 à 8003 dans compose.yml
sed -i 's/published: 8000/published: 8003/' compose.yml

# Lancer les conteneurs
sudo docker compose -f compose.yml up -d

echo "=== Installation terminée ==="
echo "Accédez à LibreNMS via : http://localhost:8003"

echo "🔥 The root password for your MySQL database is set to RemoteLabz-2022$"
echo "🔥 The user password for the remotelabz MySQL database is set to Mysql-Pa33wrd$"
echo "Your .env.local will be configured with this default password. If you choose to change it, don't forget to modify your .env.local file"
echo "To change it, you can read the documentation online httsp://docs.remotelabz.com"
