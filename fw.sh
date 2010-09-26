#!/bin/bash

. ./fw.cfg

function iface_ip()
{
    local iface=$1
    local iface_i
    local data
    for((i=0; $i<${#IFACE_IP[*]}; ++i))
    do
        data=(${IFACE_IP[$i]})
        iface_i=${data[0]}
        if [[ $iface_i == $iface ]]
        then
            echo -n ${data[1]}
            return
        fi
    done
    echo -n ''
}

function iface_ips()
{
    local iface=$1
    local iface_i
    local data
    local ip_i
    for((i=0; $i<${#IFACE_IP[*]}; ++i))
    do
        data=(${IFACE_IP[$i]})
        iface_i=${data[0]}
        if [[ $iface_i == $iface ]]
        then
            echo -n ${data[1]}
            for((ip_i = 2; $ip_i < ${#data[*]}; ++i)) do
                echo -n " ${data[$i]}"
            done
            return
        fi
    done
    echo -n ''
}

function ipset_create()
{
    local name=$1
    $IPSET -X $name
    $IPSET -N $*
    $IPSET -F $name
}

function ipset_add_ports()
{
    local name=$1
    local ports=$2
    local begin=${ports%:*}
    local end=${ports#*:}
    # Порт может быть номером, диапазоном номеров или именем, поэтому не для
    # диапазона делаем без цикла
    if [[ $begin == $end ]]
    then
         $IPSET -A $name $begin
    else
         for((i=$begin;$i<=$end;++i))
         do
             $IPSET -A $name $i
         done
     fi

}

function nat_rules_for_vz_service()
{
    local proto=$1
    local ip=$2
    local dport=$3
    local to_dest=$4
    $IPTABLES -t nat -A PREROUTING -p $proto -d $ip --dport $dport -j DNAT --to-destination $to_dest
    $IPTABLES -t nat -A OUTPUT -p $proto -d $ip --dport $dport -j DNAT --to-destination $to_dest
}

# На время очистки правил запретим все входящие, исходящие и транзитные.
$IPTABLES -P INPUT DROP
$IPTABLES -P FORWARD DROP
$IPTABLES -P OUTPUT DROP

$IPTABLES -F
$IPTABLES -t nat -F
$IPTABLES -t mangle -F

$IPTABLES -X
$IPTABLES -t nat -X
$IPTABLES -t mangle -X

# Наборы портов

ipset_create inet_open_ports_tcp portmap --from 1 --to $PORTMAX
ipset_create inet_open_ports_udp portmap --from 1 --to $PORTMAX
for ports in $INET_OPEN_PORTS_TCP
do
    ipset_add_ports inet_open_ports_tcp $ports
done
for ports in $INET_OPEN_PORTS_UDP
do
    ipset_add_ports inet_open_ports_udp $ports
done

ipset_create iface_nets nethash

# Правило для проверки TCP-пакетов на корректность
$IPTABLES -N tcp_check
# Препятствуем попытке отправить пакет якобы от нашего имени.
$IPTABLES -A tcp_check -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -m limit --limit 5/minute -j LOG --log-prefix 'Attack? New SYN,ACK: ' --log-ip-options
$IPTABLES -A tcp_check -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset
$IPTABLES -A tcp_check -p tcp ! --syn -m state --state NEW -m limit --limit 5/minute -j LOG --log-prefix "Attack? New tcp not syn: " --log-ip-options
$IPTABLES -A tcp_check -p tcp ! --syn -m state --state NEW -j DROP

# Анализ пакетов icmp
$IPTABLES -N in_icmp_packets
$IPTABLES -A in_icmp_packets -p icmp -s 0/0 --icmp-type echo-request -j ACCEPT
$IPTABLES -A in_icmp_packets -p icmp -s 0/0 --icmp-type time-exceeded -j ACCEPT

# Анализ пакетов tcp
$IPTABLES -N in_tcp_packets

$IPTABLES -A in_tcp_packets -j tcp_check

# Разрешаем некоторые входящие соединения по TCP
for((i=0; $i<${#INET_IFACES[*]}; ++i))
do
    $IPTABLES -A in_tcp_packets -i ${INET_IFACES[$i]} -p tcp -m set --set inet_open_ports_tcp dst -j ACCEPT
done

for((i=0; $i<${#LAN_IFACES[*]}; ++i))
do
  $IPTABLES -A in_tcp_packets -i ${LAN_IFACES[$i]} -p tcp -j ACCEPT
done

# Анализ пакетов udp
$IPTABLES -N in_udp_packets
$IPTABLES -F in_udp_packets

for((i=0; $i<${#INET_IFACES[*]}; ++i))
do
    $IPTABLES -A in_udp_packets -i ${INET_IFACES[$i]} -p udp -m set --set inet_open_ports_udp dst -j ACCEPT
done

for((i=0; $i<${#LAN_IFACES[*]}; ++i))
do
  $IPTABLES -A in_udp_packets -i ${LAN_IFACES[$i]} -p udp -j ACCEPT
done

# Правила для проверки соответствия интерфейсов и адресов, которые заданы в массиве IFACE_NETS.
$IPTABLES -N known_nets
$IPTABLES -N known_nets_wrong
$IPTABLES -A known_nets_wrong -m limit --limit 5/minute -j LOG --log-prefix 'Wrong interface: ' --log-ip-options
$IPTABLES -A known_nets_wrong -j DROP
for((i=${#IFACE_NETS[*]}-1; $i>=0; --i))
do
  net_data=(${IFACE_NETS[$i]})
  iface=${net_data[0]}
  for((j=${#net_data[*]}-1; $j>=1; --j))
  do
    net=${net_data[$j]}
    $IPSET -A iface_nets $net
    $IPTABLES -I known_nets 1 -s $net -i $iface -j RETURN
  done
  $IPTABLES -A known_nets -i $iface -j known_nets_wrong
done
$IPTABLES -A known_nets -m set --set iface_nets src -j known_nets_wrong

# Цепочка INPUT

# Разрешаем входящие пакеты установленных соединений.
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Разрешаем входящие локально сгенерированные пакеты.
$IPTABLES -A INPUT -i lo -j ACCEPT

# Проверяем, соответствует ли адрес интерфейсу
$IPTABLES -A INPUT -j known_nets

$IPTABLES -A INPUT -p tcp --jump in_tcp_packets
$IPTABLES -A INPUT -p udp --jump in_udp_packets
$IPTABLES -A INPUT -p icmp --jump in_icmp_packets

# Записываем (частично) в лог пакеты, которые не прошли правила.
$IPTABLES -A INPUT -m limit --limit 5/minute -j LOG --log-prefix 'Bad input packet: ' --log-ip-options # --log-level debug
$IPTABLES -A INPUT -j DROP

# Цепочка FORWARD

$IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Проверяем, соответствует ли адрес интерфейсу
$IPTABLES -A FORWARD -j known_nets

# Разрешаем форвард для всех адресов локальной сети (может потребуется поменять)
for((i=0; $i<${#LAN_IFACES[*]}; ++i))
do
    $IPTABLES -A FORWARD -i ${LAN_IFACES[$i]} -j ACCEPT
done

# OpenVZ для таблицы filter
for((i=0; $i<${#VZ_SERVERS[*]}; ++i)) 
do
    data=(${VZ_SERVERS[$i]})
    proto=${data[0]}
    ip=${data[1]}
    for((porti=2; $porti<${#data[*]}; ++porti))
    do
        port=${data[$porti]}
        $IPTABLES -A FORWARD -o $VZ_IFACE -p $proto -d $ip --dport $port -j ACCEPT
    done
done

# Записываем (частично) в лог пакеты, которые не прошли правила.
$IPTABLES -A FORWARD -m limit --limit 5/minute -j LOG --log-prefix 'Bad forward packet: ' --log-ip-options # --log-level debug
$IPTABLES -A FORWARD -j DROP

# Цепочка OUTPUT

# Роутер
for((i=0; i<${#INET_IFACES[*]}; ++i)) {
    iface=${INET_IFACES[$i]};
    ip=$(iface_ip $iface);
    if [[ $ip == '' ]]
    then
        $IPTABLES -t nat -A POSTROUTING -o $iface -j MASQUERADE
    else
        $IPTABLES -t nat -A POSTROUTING -o $iface -j SNAT --to-source $ip
    fi
}

# OpenVZ для таблицы nat
for((iface_i=0; $iface_i<${#IFACE_IP[*]}; ++iface_i))
do
    ifaceip=(${IFACE_IP[$iface_i]})
    for((ip_i=1; $ip_i<${#ifaceip[*]}; ++ip_i))
    do
        ip=${ifaceip[$ip_i]}

	for((vz_i=0; $vz_i<${#VZ_SERVERS[*]}; ++vz_i))
	do
	    vz_data=(${VZ_SERVERS[$vz_i]})
	    proto=${vz_data[0]}
	    to_dest=${vz_data[1]}

	    for((port_i=2; $port_i<${#vz_data[*]}; ++port_i))
	    do
		port=${vz_data[$port_i]}
		nat_rules_for_vz_service $proto $ip $port $to_dest
            done
        done
    done
done

# Устанавливаем основные правила по умолчанию.
$IPTABLES -P INPUT DROP
$IPTABLES -P FORWARD DROP
$IPTABLES -P OUTPUT ACCEPT

