#!/bin/bash
# Скрипт установки OpenVPN на операционные системы семейства CentOS

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
	cat /etc/openvpn/keys/easy-rsa-master/easyrsa3/pki/issued/$1.crt >> ~/$1.ovpn
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
				
				#Правим скрипт сетевых настроек.
				echo '#!/bin/sh' > /root/ipt-set
				echo "IF_EXT=\"$IF_EXT\"
IPT=\"/sbin/iptables\"
IPT6=\"/sbin/ip6tables\"
# flush
\$IPT --flush
\$IPT -t nat --flush
\$IPT -t mangle --flush
\$IPT -X
\$IPT6 --flush
# loopback
\$IPT -A INPUT -i lo -j ACCEPT
\$IPT -A OUTPUT -o lo -j ACCEPT
# default
\$IPT -P INPUT DROP
\$IPT -P OUTPUT DROP
\$IPT -P FORWARD DROP
\$IPT6 -P INPUT DROP
\$IPT6 -P OUTPUT DROP
\$IPT6 -P FORWARD DROP
# allow forwarding" >> /root/ipt-set

				echo 'echo 0 > /proc/sys/net/ipv4/ip_forward' >> /root/ipt-set

				echo '# INPUT chain
# #########################################
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# ssh
$IPT -A INPUT -i $IF_EXT -p tcp --dport 22 -j ACCEPT' >> /root/ipt-set

				echo '# OUTPUT chain
# #########################################
$IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT' >> /root/ipt-set
				
				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
							semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
						fi
					fi
				fi

				yum remove openvpn -y
				rm -rf /etc/openvpn
				echo ""
				echo "OpenVPN удалён!"
			else
				echo ""
				echo "Удаление отменено!"
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
	echo "Несколько вопросов перед началом установки"
	echo "Вы можете оставлять параметры по умолчанию и просто нажимать «Enter», если они вас устраивают."
	echo "Если хотите изменить параметр, то сотрите предлагаемое значение и введите своё"
	echo ""
	echo "Для начала введите IP адрес, на который OpenVPN будет принимать подкючения"
	echo "Если автоматически определённый IP адрес правильный, просто нажмите Enter"
	read -p "Определён IP адрес: " -e -i $IP IP
	echo ""
	echo "Какой протокол будем использовать?"
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
	read -p "Порт: " -e -i 443 PORT
	echo ""
	echo "Какой DNS вы хотите использовать в своей VPN?"
	echo "   1) Текущие системные настройки"
	echo "   2) Google"
	read -p "DNS [1-2]: " -e -i 2 DNS
	echo ""
	echo "Укажите имя первого сертификата пользователя"
	echo "Используйте только буквы, никаких спецсимволов"
	read -p "Имя пользователя: " -e -i client CLIENT
	echo ""
	echo "А теперь введите начальные данные для корневого сертификата"
	echo "Они ни на что не влияют"
	echo "Вам будут предложены дефолтные значения"
	echo "Просто жмите Enter если они вас устраивают."
	echo "Если нет, то сотрите и введите свои."
	read -p "Регион: " -e -i Russia EASYRSA_REQ_PROVINCE
	read -p "Город: " -e -i Moscow EASYRSA_REQ_CITY
	read -p "Название организации: " -e -i RosComNadzor EASYRSA_REQ_ORG
	read -p "E-mail: " -e -i admin@rkn.ru EASYRSA_REQ_EMAIL
	read -p "Подразделение: " -e -i OtdelBeshennogoPrintera EASYRSA_REQ_OU
	echo "Отлично. Сейчас обновим сервер и выполним первичную установку OpenVPN."
	read -n1 -r -p "Нажмите любую кнопку для продолжения..."
	yum install epel-release -y
	yum update -y
	#yum upgrade -y
	yum install openvpn openssl iptables wget zip unzip -y
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
	echo 'set_var EASYRSA_KEY_SIZE "2048"' >> /etc/openvpn/keys/easy-rsa-master/easyrsa3/vars
	echo 'set_var EASYRSA_DIGEST "sha256"' >> /etc/openvpn/keys/easy-rsa-master/easyrsa3/vars
	# Создаём PKI, создаём CA, ключ DH а также сертификаты сервера и клиента
	./easyrsa init-pki
	echo "Сейчас будет создан корневой сертификат"
	echo "На запрос Enter Pem pass phrase пароля придумайте и "
	echo "введите сложный пароль два раза. После кажждого ввода жмите Enter"
	read -n1 -r -p "Нажмите любую кнопку для продолжения..."
	./easyrsa --batch build-ca
	echo ""
	echo ""
	echo "Создаем ключ Диффи-Хелмана..."
	echo ""
	echo ""
	echo "Это займет МНОГО времени!"
	echo ""
	echo ""
	./easyrsa gen-dh
	echo "Сейчас будут созданы сертификаты сервера и клиента,"
	echo "а также список отозваных сертификатов"
	echo "На запрос key: введите пароль от корневого сертификата."
	read -n1 -r -p "Нажмите любую кнопку для продолжения..."
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
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1" ' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1) 
		# Получакм DNS из resolv.conf и используем их для OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2) 
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "remote-cert-eku \"TLS Web Client Authentication\"
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
	echo "server.conf создан..."

	#Определим названием внешнего интерфейса. Не самый оптимальный вариант, но сходу лучше не придумал
	IF_EXT=$(ip route get 8.8.8.8 | sed -nr 's/.*dev ([^\ ]+).*/\1/p')
	echo "Определили внешний интерфейс как $IF_EXT..."
	#Создадим скрипт сетевых настроек. Он будет применятся при каждой перезагрузке
	echo '#!/bin/sh' > /root/ipt-set
	echo "IF_EXT=\"$IF_EXT\"
IF_OVPN=\"tun0\"
OVPN_PORT=\"$PORT\"
IPT=\"/sbin/iptables\"
IPT6=\"/sbin/ip6tables\"
# flush
\$IPT --flush
\$IPT -t nat --flush
\$IPT -t mangle --flush
\$IPT -X
\$IPT6 --flush
# loopback
\$IPT -A INPUT -i lo -j ACCEPT
\$IPT -A OUTPUT -o lo -j ACCEPT
# default
\$IPT -P INPUT DROP
\$IPT -P OUTPUT DROP
\$IPT -P FORWARD DROP
\$IPT6 -P INPUT DROP
\$IPT6 -P OUTPUT DROP
\$IPT6 -P FORWARD DROP
# allow forwarding" >> /root/ipt-set

	echo 'echo 1 > /proc/sys/net/ipv4/ip_forward' >> /root/ipt-set

	echo '# NAT
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
# openvpn' >> /root/ipt-set

	echo "\$IPT -A INPUT -i \$IF_EXT -p $PROTOCOL --dport \$OVPN_PORT -j ACCEPT" >> /root/ipt-set

	echo '# FORWARD chain
# #########################################
$IPT -A FORWARD -i $IF_OVPN -o $IF_EXT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -i $IF_EXT -o $IF_OVPN -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -s 10.8.0.0/24 -d 10.8.0.0/24 -j ACCEPT
# OUTPUT chain
# #########################################
$IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT' >> /root/ipt-set

	#Установим права на запуск
	chmod 755 /root/ipt-set
	echo "Файл ipt-set создан..."
	#Сделаем свою службу для  запуска скрипта ipt-set
	echo '[Unit]
Description=Iptables Settings Service
After=network.target
[Service]
Type=oneshot
User=root
ExecStart=/root/ipt-set
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/ipt-settings.service
	chmod 644 /etc/systemd/system/ipt-settings.service
	echo "Служба для запуска ipt-set создана..."
	#Добавим в автозагрузку
	systemctl enable ipt-settings
	#И запустим
	systemctl start ipt-settings
	# Если включен SELinux, разрешим порт
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
				# semanage по умолчанию не доступен CentOS 6
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
				echo "Порт в semanage разрешён..."
			fi
		fi
	fi
	# And finally, restart OpenVPN
	echo "Запуск серера OpenVPN..."
	if pgrep systemd-journal; then
		systemctl restart openvpn@server.service
		systemctl enable openvpn@server.service
	else
		service openvpn restart
		chkconfig openvpn on
	fi

	# Client-common.txt будет нашим шаблоном для добавления новых пользователей позже
	echo "client
dev tun
proto $PROTOCOL
remote $IP $PORT
resolv-retry infinite
nobind
block-outside-dns
persist-key
persist-tun
mute-replay-warnings
remote-cert-eku \"TLS Web Server Authentication\"
remote-cert-tls server
tls-client
verb 3" > /etc/openvpn/client-common.txt
	# Создаём client.ovpn
	newclient "$CLIENT"
	echo ""
	echo "Сделано!"
	echo ""
	echo "Клиентский конфиг в файле" ~/"$CLIENT.ovpn"
	echo "Если нужны еще клиенты, то запустите скрипт еще раз."
fi
