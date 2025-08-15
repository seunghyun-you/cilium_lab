#!/usr/bin/env bash

echo ">>>> Initial Config Start <<<<"


echo "[TASK 0] Setting eth2"
chmod 600 /etc/netplan/01-netcfg.yaml
chmod 600 /etc/netplan/50-vagrant.yaml

cat << EOT >> /etc/netplan/50-vagrant.yaml
    eth2:
      addresses:
      - 192.168.20.200/24
EOT

netplan apply


echo "[TASK 1] Setting Profile & Bashrc"
echo 'alias vi=vim' >> /etc/profile
echo "sudo su -" >> /home/vagrant/.bashrc
ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime


echo "[TASK 2] Disable AppArmor"
systemctl stop ufw && systemctl disable ufw >/dev/null 2>&1
systemctl stop apparmor && systemctl disable apparmor >/dev/null 2>&1


echo "[TASK 3] Add Kernel setting - IP Forwarding"
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sysctl -p >/dev/null 2>&1


echo "[TASK 4] Setting Dummy Interface"
modprobe dummy
ip link add loop1 type dummy
ip link set loop1 up
ip addr add 10.10.1.200/24 dev loop1

ip link add loop2 type dummy
ip link set loop2 up
ip addr add 10.10.2.200/24 dev loop2


echo "[TASK 5] Install Packages"
export DEBIAN_FRONTEND=noninteractive
apt update -qq >/dev/null 2>&1
apt-get install net-tools jq tree ngrep tcpdump arping -y -qq >/dev/null 2>&1


echo "[TASK 6] Install Apache"
apt install apache2 -y >/dev/null 2>&1
echo -e "<h1>Web Server : $(hostname)</h1>" > /var/www/html/index.html


echo "[TASK 7] Configure FRR"
apt install frr -y >/dev/null 2>&1
sed -i "s/^bgpd=no/bgpd=yes/g" /etc/frr/daemons

NODEIP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
cat << EOF >> /etc/frr/frr.conf
!
router bgp 65000
  bgp router-id $NODEIP
  bgp graceful-restart
  no bgp ebgp-requires-policy
  bgp bestpath as-path multipath-relax
  maximum-paths 4
  network 10.10.1.0/24
EOF


systemctl daemon-reexec >/dev/null 2>&1
systemctl restart frr >/dev/null 2>&1
systemctl enable frr >/dev/null 2>&1


echo ">>>> Initial Config End <<<<"
