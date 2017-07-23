#!/bin/bash
# Универсальный скрипт установки OpenVPN на операционные системы семейства CentOS

# Этот скрипт будет работать толко на CentOS и, возможно, на его
# производных дистрибутивах



if [[ "$EUID" -ne 0 ]]; then
	echo "Этот скрипт нужно запускать с правами root"
	exit 2
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "Не обнаружена поддержка TUN. Включите TUN перед запуском скрипта"
	exit 3
fi

if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 слишком старый, установка не возможна"
	exit 4
fi
if [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Ваша операционная система не из семейства CentOS"
	exit 5
fi

newclient () {
	# Создаем файл client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/keys/easy-rsa-master/easyrsa3/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/keys/easy-rsa-master/easyrsa3/pki/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/keys/easy-rsa-master/easyrsa3/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

# Пробуем получить наш IP адрес
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -4qO- "http://whatismyip.akamai.com/")
fi

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "OpenVPN уже установлен"
		echo ""
		echo "Что вы хотите сделать?"
		echo "   1) Добавить пользователя"
		echo "   2) Удалить сущетвующего пользвателя"
		echo "   3) Удалить OpenVPN"
		echo "   4) Завершить работу скрипта"
		read -p "Выберите вариант [1-4]: " option
		case $option in
			1) 
			echo ""
			echo "Введите имя для сертификата нового пользователя"
			echo "Используйте только буквы, никаких спецсимволов"
			read -p "Имя пользователя: " -e -i client CLIENT
			cd /etc/openvpn/keys/easy-rsa-master/easyrsa3/
			./easyrsa build-client-full $CLIENT nopass
			# Создаем client.ovpn
			newclient "$CLIENT"
			echo ""
			echo "Пользователь $CLIENT добавлен, конфигурационный файл в текушей папке" ~/"$CLIENT.ovpn"
			exit
			;;
			2)
			# Удаляем пользователя
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/keys/easy-rsa-master/easyrsa3/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "У сервера нет ни одного пользователя!"
				exit 6
			fi
			echo ""
			echo "Выберите одного из существующих пользователей"
			tail -n +2 /etc/openvpn/keys/easy-rsa-master/easyrsa3/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Выберите пользователя [1]: " CLIENTNUMBER
			else
				read -p "Выберите пользователя [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/keys/easy-rsa-master/easyrsa3/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/keys/easy-rsa-master/easyrsa3/
			./easyrsa --batch revoke $CLIENT
			./easyrsa gen-crl
			rm -rf pki/reqs/$CLIENT.req
			rm -rf pki/private/$CLIENT.key
			rm -rf pki/issued/$CLIENT.crt
			rm -rf /etc/openvpn/crl.pem
			cp /etc/openvpn/keys/easy-rsa-master/easyrsa3/pki/crl.pem /etc/openvpn/crl.pem
			chown nobody:$GROUPNAME /etc/openvpn/crl.pem
			echo ""
			echo "Сертификат пользователя $CLIENT отозван"
			exit
			;;
			3) 
			echo ""
			read -p "Вы действительно хотите удалить OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					# Использование как постоянных, так и не постоянных правил, чтобы избежать перезагрузки.
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
				else
					IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
					if iptables -L -n | grep -qE '^ACCEPT'; then
						iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					fi
				fi
				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
							semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
						fi
					fi
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				echo ""
				echo "OpenVPN удалён!"
			else
				echo ""
				echo "Не удалось удалить!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo 'Начинаем установку OpenVPN вместе с SecFAll.com'
	echo ""
	# Установка OpenVPN и создание первого пользователя
	echo "Пара вопросов перед началом установки"
	echo "Вы можете оставлять параметры по умолчанию и просто нажимать «Enter», если они вас устраивают."
	echo ""
	echo "Для начала укажите IP адрес, на который OpenVPN будет принимать подкючения"
	read -p "IP адрес: " -e -i $IP IP
	echo ""
	echo "Какой протокл будем использовать?"
	echo "   1) UDP (рекомендуется)"
	echo "   2) TCP"
	read -p "Протокол [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo ""
	echo "На какой порт будем принимать подключения (443 рекомендуется)?"
	read -p "Port: " -e -i 443 PORT
	echo ""
	echo "Какой DNS вы хотите использовать в своей VPN?"
	echo "   1) Текщие системные настройки"
	echo "   2) Google"
	read -p "DNS [1-2]: " -e -i 2 DNS
	echo ""
	echo "И в завершении укажите имя первого сертификата пользователя"
	echo "Используйте только буквы, никаких спецсимволов"
	read -p "Имя пользователя: " -e -i client CLIENT
	echo ""
	echo "А теперь введите начальные данные для корневого сертификата"
	echo "Они ни на что не влияют"
	echo "В скобках вам будут предложены дефолтные значения"
	echo "Просто жмите Enter если они вас устраивают"
	read -p "Регион [Russia]" -e -i Russia EASYRSA_REQ_PROVINCE
	read -p "Город [Moscow]" -e -i Moscow EASYRSA_REQ_CITY
	read -p "Название организации [RosComNadzor]" -e -i RosComNadzor EASYRSA_REQ_ORG
	read -p "E-mail [admin@rkn.ru" -e -i admin@rkn.ru EASYRSA_REQ_EMAIL
	read -p "Подразделение [OtdelBesnennogoPrintera]" -e -i OtdelBesnennogoPrintera EASYRSA_REQ_OU
	echo "Отлично, информации достаточно. Сейчас мы установим OpenVPN сервер"
	read -n1 -r -p "Нажмите любую кнопку для продолжения..."
	yum install epel-release -y
	yum update -y
	yum upgrade -y
	yum install openvpn iptables wget zip unzip -y
	# Удаляем старые версииf easy-rsa
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	if [[ -d /etc/openvpn/keys/ ]]; then
		rm -rf /etc/openvpn/keys/
	fi
	# Скачиваем и распаковываем easy-rsa
	mkdir /etc/openvpn/keys
	cd /etc/openvpn/keys
	wget https://github.com/OpenVPN/easy-rsa/archive/master.zip
	unzip master.zip
	cd /etc/openvpn/keys/easy-rsa-master/easyrsa3
	# Создадим файл с настройками
	cp vars.example vars
	# Засунем в него дефолтные поля сертификата
	echo 'set_var EASYRSA_REQ_PROVINCE "$EASYRSA_REQ_PROVINCE"' >> /etc/openvpn/keys/easy-rsa-master/easyrsa3/vars
	echo 'set_var EASYRSA_REQ_CITY "$EASYRSA_REQ_CITY"' >> /etc/openvpn/keys/easy-rsa-master/easyrsa3/vars
	echo 'set_var EASYRSA_REQ_ORG "$EASYRSA_REQ_ORG"' >> /etc/openvpn/keys/easy-rsa-master/easyrsa3/vars
	echo 'set_var EASYRSA_REQ_EMAILE "$EASYRSA_REQ_EMAIL"' >> /etc/openvpn/keys/easy-rsa-master/easyrsa3/vars
	echo 'set_var EASYRSA_REQ_OU "$EASYRSA_REQ_OU"' >> /etc/openvpn/keys/easy-rsa-master/easyrsa3/vars
	echo 'set_var EASYRSA_KEY_SIZE "4096"' >> /etc/openvpn/keys/easy-rsa-master/easyrsa3/vars
	echo 'set_var EASYRSA_DIGEST "sha256"' >> /etc/openvpn/keys/easy-rsa-master/easyrsa3/vars
	# Создаём PKI, создаём CA, ключ DH а также сертификаты сервера и клиента
	./easyrsa init-pki
	echo "Сейчас будет создан корневой сертификат"
	echo "На запрос Enter Pem pass phrase пароля придумайте и "
	echo "введите сложный пароль два раза. После кажждого ввода жмите Enter"
	read -n1 -r -p "Нажмите любую кнопку для продолжения..."
	./easyrsa --batch build-ca
	echo "Создаем ключч Диффи-Хелмана..."
	./easyrsa gen-dh
	echo "Создаем сертификат сервера..."
	./easyrsa build-server-full server nopass
	echo "Создаем сертификат пользователя..."
	./easyrsa build-client-full $CLIENT nopass
	echo "Создаем список отозваных сертификатов..."
	./easyrsa gen-crl
	# Готовые сертификаты в рабочую папку сервера
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	echo "Создаем ключ tls-auth..."
	openvpn --genkey --secret /etc/openvpn/ta.key
	echo "Настраиваем сервер..."
	echo "port $PORT
proto $PROTOCOL
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh.pem
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
dh dh.pem
crl-verify crl.pem
 
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >> /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1" ' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1) 
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2) 
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "remote-cert-eku "TLS Web Client Authentication"
keepalive 10 120
tls-server
tls-auth ta.key 0
tls-timeout 120
auth SHA512
cipher AES-256-CBC
comp-lzo
max-clients 10
 
user nobody
group nobody
 
persist-key
persist-tun
 
status openvpn-status.log
log openvpn.log
verb 4" >> /etc/openvpn/server.conf

	#Создадим файл ipt-set
	#Определим названием внешенего интерфейса. Не самый оптимальный вариант, но сходу лучше не придумал
	IF_EXT=$(ip r l | grep default | cut -d " " -f 5)
	echo "#!/bin/sh
IF_EXT="$IF_EXT"
IF_OVPN="tun0"
OVPN_PORT="$PORT"
IPT="/sbin/iptables"
IPT6="/sbin/ip6tables"

# flush
$IPT --flush
$IPT -t nat --flush
$IPT -t mangle --flush
$IPT -X
$IPT6 --flush

# loopback
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# default
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP
$IPT6 -P INPUT DROP
$IPT6 -P OUTPUT DROP
$IPT6 -P FORWARD DROP

# allow forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# NAT
# #########################################
# SNAT - local users to out internet
$IPT -t nat -A POSTROUTING -o $IF_EXT -j MASQUERADE

# INPUT chain
# #########################################
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# ssh
$IPT -A INPUT -i $IF_EXT -p tcp --dport 22 -j ACCEPT
# VPN
$IPT -A INPUT -i $IF_OVPN -p icmp -s 10.8.0.0/24 -j ACCEPT
# DNS
$IPT -A INPUT -i $IF_OVPN -p udp --dport 53 -s 10.8.0.0/24 -j ACCEPT
# openvpn
$IPT -A INPUT -i $IF_EXT -p udp --dport $OVPN_PORT -j ACCEPT
# squid
$IPT -A INPUT -i $IF_OVPN -p tcp --dport $SQUID_PORT -j ACCEPT
$IPT -A INPUT -i $IF_OVPN -p udp --dport $SQUID_PORT -j ACCEPT

# FORWARD chain
# #########################################
$IPT -A FORWARD -i $IF_OVPN -o $IF_EXT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -i $IF_EXT -o $IF_OVPN -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -s 10.8.0.0/24 -d 10.8.0.0/24 -j ACCEPT

# OUTPUT chain
# #########################################
$IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

	# Enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
	else
		chmod +x $RCLOCAL
		# Set NAT for the VPN subnet
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# If iptables has at least one REJECT rule, we asume this is needed.
			# Not the best approach but I can't think of other and this shouldn't
			# cause problems.
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	# If SELinux is enabled and a custom port or TCP was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
				# semanage isn't available in CentOS 6 by default
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
			fi
		fi
	fi
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# Try to detect a NATed connection and ask about it to potential LowEndSpirit users
	EXTERNALIP=$(wget -4qO- "http://whatismyip.akamai.com/")
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (e.g. LowEndSpirit), I need to know the external IP"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-common.txt
	# Generates the custom client.ovpn
	newclient "$CLIENT"
	echo ""
	echo "Finished!"
	echo ""
	echo "Your client configuration is available at" ~/"$CLIENT.ovpn"
	echo "If you want to add more clients, you simply need to run this script again!"
fi
