#!/bin/bash
# description: 安装OpenVPN


source /etc/profile
OPENVPN_VERSION="2.4.6"

# 1.安装相关组件
yum -y install lrzsz net-tools vim* unzip iptables iptables-devel iptables-services
yum -y install openssl openssl-devel lzo lzo-devel pam pam-devel rpm-build expect
yum -y update
systemctl stop firewalld
systemctl disable firewalld
systemctl enable iptables
systemctl start iptables
cat > /etc/sysconfig/iptables<<EOF
# sample configuration for iptables service
# you can edit this manually or use system-config-firewall
# please do not ask us to add additional ports/services to this default configuration
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 52222 -j ACCEPT
COMMIT
EOF
systemctl restart iptables

# 2.创建工作目录
for i in apps apps_install conf data logs scripts src webapps; do mkdir -p /opt/$i; done

# 3.下载安装包
cd /opt/src
[[ -f openvpn-${OPENVPN_VERSION}.tar.gz ]] && rm -f openvpn-${OPENVPN_VERSION}.tar.gz
[[ -f easy-rsa-master.zip ]] && rm -f easy-rsa-master.zip
wget -c https://swupdate.openvpn.org/community/releases/openvpn-${OPENVPN_VERSION}.tar.gz
wget -c https://github.com/OpenVPN/easy-rsa/archive/master.zip -O easy-rsa-master.zip

# 4.编译RPM包并安装
yum -y remove openvpn openvpn-devel
[[ -d /etc/openvpn ]] && rm -rf /etc/openvpn
rpmbuild -tb openvpn-${OPENVPN_VERSION}.tar.gz
rpm -ivh /root/rpmbuild/RPMS/x86_64/openvpn-${OPENVPN_VERSION}*.x86_64.rpm
rpm -ivh /root/rpmbuild/RPMS/x86_64/openvpn-devel-${OPENVPN_VERSION}*.x86_64.rpm
[[ -d /root/rpmbuild ]] && /bin/rm -rf /root/rpmbuild

# 5.配置easy-rsa
[[ -d /usr/local/easy-rsa ]] && rm -rf /usr/local/easy-rsa
unzip easy-rsa-master.zip && mv easy-rsa-master /usr/local/easy-rsa && cp /usr/local/easy-rsa/easyrsa3/{vars.example,vars}
easyrsa3_vars="/usr/local/easy-rsa/easyrsa3/vars"
sed -i '/PWD/s|#set_var EASYRSA|set_var EASYRSA|g' $easyrsa3_vars
sed -i 's|$PWD|/usr/local/easy-rsa/easyrsa3|g' $easyrsa3_vars
sed -i '/EASYRSA_REQ_COUNTRY/s|#set_var EASYRSA|set_var EASYRSA|g' $easyrsa3_vars
sed -i '/EASYRSA_REQ_PROVINCE/s|#set_var EASYRSA|set_var EASYRSA|g' $easyrsa3_vars
sed -i '/EASYRSA_REQ_CITY/s|#set_var EASYRSA|set_var EASYRSA|g' $easyrsa3_vars
sed -i '/EASYRSA_REQ_ORG/s|#set_var EASYRSA|set_var EASYRSA|g' $easyrsa3_vars
sed -i '/EASYRSA_REQ_EMAIL/s|#set_var EASYRSA|set_var EASYRSA|g' $easyrsa3_vars
sed -i '/EASYRSA_REQ_OU/s|#set_var EASYRSA|set_var EASYRSA|g' $easyrsa3_vars

# 6.配置证书及密钥
/usr/local/easy-rsa/easyrsa3/easyrsa init-pki
expect -c 'set timeout 5;spawn /usr/local/easy-rsa/easyrsa3/easyrsa build-ca;expect "phrase:";send "963852741\r";send "963852741\r";send "\r";interact'
expect -c 'set timeout 5;spawn /usr/local/easy-rsa/easyrsa3/easyrsa gen-req OpenVPN-Server nopass;expect "Common Name";send "\r";interact'
expect -c 'set timeout 5;spawn /usr/local/easy-rsa/easyrsa3/easyrsa sign-req server OpenVPN-Server;expect "Confirm";send "yes\r";expect "phrase";send "963852741\r";interact'
/usr/local/easy-rsa/easyrsa3/easyrsa gen-dh

/bin/cp -f /usr/local/easy-rsa/easyrsa3/pki/ca.crt /etc/openvpn/
/bin/cp -f /usr/local/easy-rsa/easyrsa3/pki/dh.pem /etc/openvpn/
/bin/cp -f /usr/local/easy-rsa/easyrsa3/pki/private/OpenVPN-Server.key /etc/openvpn/
/bin/cp -f /usr/local/easy-rsa/easyrsa3/pki/issued/OpenVPN-Server.crt /etc/openvpn/

# 7.配置OpenVPN
[[ `grep -c "^openvpn:" /etc/passwd` = 0 ]] && groupadd openvpn && useradd -g openvpn -c 'OpenVPN User' -s /sbin/nologin -M openvpn
install -o openvpn -g openvpn -d /var/log/openvpn
openvpn --genkey --secret /etc/openvpn/ta.key
/bin/cp -f /usr/share/doc/openvpn-${OPENVPN_VERSION}/sample/sample-config-files/server.conf /etc/openvpn/

server_conf="/etc/openvpn/server.conf"
sed -i "s/port 1194/port 11940/g" $server_conf
#sed -i "s/;proto tcp/proto tcp/g" $server_conf
#sed -i "s/proto udp/#proto udp/g" $server_conf
sed -i "s/cert server.crt/cert OpenVPN-Server.crt/g" $server_conf
sed -i "s/key server.key/key OpenVPN-Server.key/g" $server_conf
sed -i "s/dh dh2048.pem/dh dh.pem/g" $server_conf
sed -i "s/;topology subnet/topology subnet/g" $server_conf
sed -i "s/server 10.8.0.0/server 10.8.66.0/g" $server_conf
sed -i 's/;push "redirect-gateway/push "redirect-gateway/g' $server_conf
sed -i 's/;push "dhcp-option DNS 208.67.222.222"/push "dhcp-option DNS 8.8.8.8"/g' $server_conf 
sed -i 's/;push "dhcp-option DNS 208.67.220.220"/push "dhcp-option DNS 8.8.4.4"/g' $server_conf
sed -i 's/;client-to-client/client-to-client/g' $server_conf
sed -i 's/;duplicate-cn/duplicate-cn/g' $server_conf
sed -i 's/;comp-lzo/comp-lzo/g' $server_conf
sed -i 's/;max-clients 100/max-clients 100/g' $server_conf
sed -i 's/;user nobody/user openvpn/g' $server_conf
sed -i 's/;group nobody/group openvpn/g' $server_conf
sed -i 's|status openvpn-status.log|#status /var/log/openvpn/openvpn-status.log|g' $server_conf
sed -i 's|;log-append  openvpn.log|#log-append /var/log/openvpn/openvpn.log|g' $server_conf
sed -i 's|explicit-exit-notify 1|#explicit-exit-notify 1|g' $server_conf
echo "reneg-sec 0" >> $server_conf
echo "script-security 3" >> $server_conf
echo "auth-user-pass-verify /etc/openvpn/checkpsw.sh via-env" >> $server_conf
echo "verify-client-cert none" >> $server_conf
echo "username-as-common-name" >> $server_conf

# 8.用iptables防火墙做nat服务器
network_interface=`ip link | egrep -v 'link|lo:|DOWN' | awk '{print $2}' | awk -F':' '{print $1}' | awk 'NR==1{print $1}'`
[[ `iptables -nvL --line | grep -c 11940` = 0 ]] && iptables -A INPUT -p tcp -m tcp --dport 11940 -j ACCEPT && iptables -A INPUT -p udp -m udp --dport 11940 -j ACCEPT
[[ `iptables -nvL --line -t nat | grep -c "10.8.66.0"` = 0 ]] && iptables -t nat -A POSTROUTING -s 10.8.66.0/24 -o $network_interface -j MASQUERADE
iptables-save > /etc/sysconfig/iptables

# 9.创建启动脚本
cat >/etc/init.d/openvpn<<EOF
#!/bin/bash
# chkconfig: 345 11 94
# description: OpenVPN


# Source function library
# Some *nix do not have an rc.d directory, so do a test first
if [ -f /etc/rc.d/init.d/functions ]; then
    . /etc/rc.d/init.d/functions
elif [ -f /etc/init.d/functions ]; then
    . /etc/init.d/functions
elif [ -f /lib/lsb/init-functions ]; then
    . /lib/lsb/init-functions
fi

RETVAL=0
prog="openvpn"
pidfile="/var/run/openvpn.pid"
lockfile="/var/lock/subsys/\$prog"
openvpn="/usr/sbin/openvpn"
openvpn_conf="/etc/openvpn/server.conf"
openvpn_work="/etc/openvpn"

start() {
    echo -n $"Starting \$prog: "
    /sbin/modprobe tun >/dev/null 2>&1
    echo 1 > /proc/sys/net/ipv4/ip_forward
    \$openvpn --daemon --writepid \$pidfile --config \$openvpn_conf --cd \$openvpn_work
    RETVAL=\$?
    echo
    [ \$RETVAL -eq 0 ] && touch \$lockfile
    return \$RETVAL
}

stop() {
    echo -n $"Stopping \$prog: "
    killproc -p \$pidfile \$openvpn
    RETVAL=\$?
    echo
    [ \$RETVAL -eq 0 ] && rm -f \$lockfile
    return \$RETVAL
}

case "\$1" in
    'start')
        start
        RETVAL=\$?
        ;;
    'stop')
        stop
        RETVAL=\$?
        ;;
    'restart')
        stop
        sleep 1
        start
        RETVAL=\$?
        ;;
    'status')
        status -p \$pidfile \$openvpn
        RETVAL=\$?
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status}"
        ;;
esac

exit \$RETVAL
EOF

chmod 755 /etc/init.d/openvpn
chkconfig openvpn on

# 10.以用户名和密码方式验证登录
cd /etc/openvpn
[[ -f checkpsw.sh ]] && rm -f checkpsw.sh
wget -c http://openvpn.se/files/other/checkpsw.sh -P /etc/openvpn/
chmod +x /etc/openvpn/checkpsw.sh
chown openvpn:openvpn /etc/openvpn/checkpsw.sh
sed -i 's|/var/log/openvpn-password.log|/dev/null|g' /etc/openvpn/checkpsw.sh
echo "acang pass" > /etc/openvpn/psw-file
#chmod 400 /etc/openvpn/psw-file
chown openvpn:openvpn /etc/openvpn/psw-file

# 11.创建客户端配置文件
#remote_ip=`ip addr | grep -A 2 "$network_interface:" | grep inet | awk '{print $2}' | awk -F'/' '{print $1}'`
remote_ip=`curl ident.me`
cat >/etc/openvpn/client.ovpn<<EOF
client
dev tun
proto udp
remote $remote_ip 11940
resolv-retry infinite
nobind
persist-key
persist-tun
mute-replay-warnings
remote-cert-tls server
cipher AES-256-CBC
comp-lzo
verb 3
reneg-sec 0
auth-user-pass
<ca>
`cat /etc/openvpn/ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat /etc/openvpn/ta.key | grep -v "^#"`
</tls-auth>
EOF

cp -rp /etc/openvpn/client.ovpn /etc/openvpn/vpn_hk_xxx.ovpn

# 12.启动OpenVPN
systemctl start openvpn
echo
sleep 2
netstat -lntup | grep openvpn | grep -v grep
echo
ps -ef | grep openvpn | grep -v grep

# 13.其他
systemctl stop ntpd
systemctl disable ntpd
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

cat > /etc/openvpn/psw-file<<EOF
apple                    12300
apple01                    12300


EOF

cat >>/var/spool/cron/root<<EOF
* * * * *    echo>/var/log/openvpn/openvpn.log;echo>/var/log/openvpn/openvpn-password.log;echo>/var/log/openvpn/openvpn-status.log
* * * * *    echo > /var/log/wtmp && echo > /var/log/btmp && cat > /var/log/secure && cat > /var/log/messages && echo > ~/.bash_history
EOF
