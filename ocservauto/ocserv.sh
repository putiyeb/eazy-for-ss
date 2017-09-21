#!/bin/bash
function Welcome()
{
clear
if [[ $EUID -ne 0 ]]; then
   echo "Error:This script must be run as root!" 1>&2
   exit 1
fi
clear
echo -n "                      Local Time :   " && date "+%F [%T]       ";
echo "            ======================================================";
echo "            |         OpenConnect(ocserv) & serverSpeeder        |";
echo "            |                                                    |";
echo "            |                                         for Debian |";
echo "            |----------------------------------------------------|";
echo "            |                  -- By shui.azurewebsites.net(YHI) |";
echo "            ======================================================";
echo;
}

function pause()
{
echo;
read -n 1 -p "Press Enter to Continue..." INP
if [ "$INP" != '' ] ; then
echo -ne '\b \n'
echo;
fi
}

function ETHER()
{
sysBits=x$(getconf LONG_BIT);
ifname=`cat /proc/net/dev | awk -F: 'function trim(str){sub(/^[ \t]*/,"",str); sub(/[ \t]*$/,"",str); return str } NR>2 {print trim($1)}'  | grep -Ev '^lo|^sit|^stf|^gif|^dummy|^vmnet|^vir|^gre|^ipip|^ppp|^bond|^tun|^tap|^ip6gre|^ip6tnl|^teql' | awk 'NR==1 {print $0}'`
}

function OWNNET()
{
echo -ne "\nSelect a IP Address from \e[33m[\e[32m0\e[0m.\e[35m${MACIP}\e[33m/\e[33m1\e[0m.\e[35m${PublicIP}\e[33m]\e[0m. \nIt will be regard as default IP Address: "
read OWNNETIP
if [ -n "$OWNNETIP" ]; then
if [ "$OWNNETIP" == '0' ]; then
    DefaultIP="${MACIP}"
elif [ "$OWNNETIP" == '1' ]; then
    DefaultIP="${PublicIP}"
else
    OWNNET;
fi
else
    DefaultIP="${MACIP}"
fi
}

function ServerIP()
{
PublicIP="$(wget -qO- checkip.amazonaws.com)"
echo -ne "Default Server IP: \e[36m${PublicIP}\e[0m .\nIf Default Server IP \e[31mcorrect\e[0m, Press Enter .\nIf Default Server IP \e[31mincorrect\e[0m, Please input Server IP :"
read iptmp
if [[ -n "$iptmp" ]]; then
    PublicIP=$iptmp
fi
sysBits=x$(getconf LONG_BIT);
ifname=`cat /proc/net/dev | awk -F: 'function trim(str){sub(/^[ \t]*/,"",str); sub(/[ \t]*$/,"",str); return str } NR>2 {print trim($1)}'  | grep -Ev '^lo|^sit|^stf|^gif|^dummy|^vmnet|^vir|^gre|^ipip|^ppp|^bond|^tun|^tap|^ip6gre|^ip6tnl|^teql' | awk 'NR==1 {print $0}'`;
echo -n $ifname |grep -q 'venet';
[ $? -eq '0' ] && oVZ='y' || oVZ='n';
MACIP="$(ifconfig $ifname |awk -F ':' '/inet addr/{ print $2}' |grep -o '[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}')";
[ "${PublicIP}" != "${MACIP}" ] && OWNNET
[ "${PublicIP}" == "${MACIP}" ] && DefaultIP="${PublicIP}";
echo -ne "Server IP: \e[35m${DefaultIP}\e[0m .\n";
MyDomain="${PublicIP}"
echo -ne "\nIf you \e[31mdo not have\e[0m a domain name, \e[33mPress Enter\e[0m! \nIf you \e[31mhave\e[0m a domain name, Please \e[32mInput your domain name\e[0m :"
read DomainTMP
if [[ -n "$DomainTMP" ]]; then
    MyDomain=$DomainTMP
    echo -ne "Domain name: \e[35m$MyDomain\e[0m .\n"
fi
DOMAIN=`echo "$MyDomain" |awk -F"[.]" '{print $(NF-1)"."$NF}'`
echo "$DOMAIN" |grep -q '[0-9]\{1,3\}.[0-9]\{1,3\}'
[ $? -eq '0' ] && DOMAIN='' || echo -ne "\nPlease put your \e[33mdomain certificate\e[0m and \e[33mprivate key\e[0m into \e[33m/etc/ocserv\e[0m when the shell script install finish! \n\e[31mrename\e[0m \e[33mcertificate\e[0m with \e[32mserver.cert.pem\e[0m\n\e[31mrename\e[0m \e[33mprivate key\e[0m with \e[32mserver.key.pem\e[0m\n"
[ $oVZ == 'y' ] && {
echo -ne "\nIt will install \e[35mocserv\e[0m and \e[35mserverSpeeder\e[0m automaticly." 
}
[ $oVZ == 'n' ] && {
echo -ne "\nIt will install \e[35mocserv\e[0m automaticly." 
}
pause;
}

function Ask_ocserv_port()
{
echo -ne "\n\e[35mInstall OpenConnect...\e[0m\n"
SSLTCP=443;
SSLUDP=443;
echo -ne "\n\e[35mPlease enter AnyConnet port\e[33m[Default:\e[32m443\e[33m]\e[0m: "
read myPORT
if [[ -n "$myPORT" ]]; then
    SSLTCP=$myPORT
    SSLUDP=$myPORT
fi
}

function Ask_ocserv_type()
{
echo -ne "\n\e[35mPlease select a type to login AnyConnet.\e[33m[\e[33m0\e[0m.\e[35mcertificate\e[33m/\e[32m1\e[0m.\e[35mpassword\e[33m]\e[0m: "
read logintype
if [ -n "$logintype" ]; then
if [ "$logintype" == '0' ]; then
    MyType='certificate'
elif [ "$logintype" == '1' ]; then
    MyType='password'
else
    Ask_ocserv_type;
fi
else
    MyType='password'
fi
}

function Ask_ocserv_password()
{
[ $MyType == 'certificate' ] && {
FILL1='CANAME'
FILL2='ORGANIZATION'
}
[ $MyType == 'password' ] && {
FILL1='UserName'
FILL2='PassWord'
}
[ -n "$FILL1" -a -n "$FILL2" ] && {
FILLIT1='shui.azurewebsites.net'
echo -ne "\n\e[35mPlease input AnyConnet $FILL1\e[33m[Default:\e[32mshui.azurewebsites.net\e[33m]\e[0m: "
read tmpFILL1
if [[ -n "$tmpFILL1" ]]; then
    FILLIT1=$tmpFILL1
fi
FILLIT2='YHIblog'
echo -ne "\n\e[35mPlease input AnyConnet $FILL2\e[33m[Default:\e[32mYHIblog\e[33m]\e[0m: "
read tmpFILL2
if [[ -n "$tmpFILL2" ]]; then
    FILLIT2=$tmpFILL2
fi
}
}

function SYSCONF()
{
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sed -i '/soft nofile/d' /etc/security/limits.conf
echo "* soft nofile 51200" >> /etc/security/limits.conf
sed -i '/hard nofile/d' /etc/security/limits.conf
echo "* hard nofile 51200" >> /etc/security/limits.conf
[ $oVZ == 'n' ] && {
cat >/etc/sysctl.conf<<EOFSYS
#This line below add by user.
#sysctl net.ipv4.tcp_available_congestion_control
#modprobe tcp_htcp
net.ipv4.ip_forward = 1
fs.file-max = 51200
net.core.wmem_max = 8388608
net.core.rmem_max = 8388608
net.core.rmem_default = 131072
net.core.wmem_default = 131072
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_rmem = 10240 81920 8388608
net.ipv4.tcp_wmem = 10240 81920 8388608
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_congestion_control = htcp
net.ipv4.icmp_echo_ignore_all = 1
#net.ipv4.tcp_fastopen = 3
EOFSYS
[ -f "/proc/sys/net/ipv4/tcp_fastopen" ] && [ -f /etc/sysctl.conf ] && sed -i 's/#net.ipv4.tcp_fastopen/net.ipv4.tcp_fastopen/g' /etc/sysctl.conf
}
sysctl -p >/dev/null 2>&1
}

function ins_ocserv()
{
BitVer='';
mkdir -p /tmp;
[ $sysBits == 'x32' ] && BitVer='i386'
[ $sysBits == 'x64' ] && BitVer='amd64'
[ -n "$BitVer" ] && {
wget --no-check-certificate -qO "/tmp/libradcli4_1.2.6-3~bpo8+1_$BitVer.deb" "http://ftp.debian.org/debian/pool/main/r/radcli/libradcli4_1.2.6-3~bpo8+1_$BitVer.deb"
wget --no-check-certificate -qO "/tmp/ocserv_0.11.6-1~bpo8+2_$BitVer.deb" "http://ftp.debian.org/debian/pool/main/o/ocserv/ocserv_0.11.6-1~bpo8+2_$BitVer.deb"
} || {
echo "Error, download fail! "
exit 1
}
bash -c "$(wget --no-check-certificate -qO- 'https://raw.githubusercontent.com/putiyeb/eazy-for-ss/master/ocservauto/src.sh')"
DEBIAN_FRONTEND=noninteractive apt-get install -y -t jessie dbus init-system-helpers libc6 libev4 libgnutls-deb0-28 libgssapi-krb5-2 libhttp-parser2.1 liblz4-1 libnettle4 libnl-3-200 libnl-route-3-200 liboath0 libopts25 libpcl1 libprotobuf-c1 libsystemd0 libtalloc2 gnutls-bin ssl-cert
dpkg -i /tmp/libradcli4_*.deb
dpkg -i /tmp/ocserv_*.deb
which ocserv >/dev/null 2>&1
[ $? -ne '0' ] && echo 'Error, Install ocerv.' && exit 1
sed -i '/exit .*/d' /etc/rc.local
sed -i '$a\iptables -t nat -A POSTROUTING -o '${ifname}' -j MASQUERADE' /etc/rc.local
sed -i '$a\iptables -I INPUT -p tcp --dport '${SSLTCP}' -j ACCEPT' /etc/rc.local
sed -i '$a\iptables -I INPUT -p udp --dport '${SSLUDP}' -j ACCEPT' /etc/rc.local
sed -i '$a\iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' /etc/rc.local
sed -i '$a\exit 0' /etc/rc.local
cat >/etc/ocserv/ocserv.conf<<EOF
#Login Type
#auth = "plain[passwd=/etc/ocserv/ocpasswd]"
auth = "certificate"
 
# TCP and UDP port number
tcp-port = $SSLTCP
#udp-port = $SSLUDP
 
server-cert = /etc/ocserv/server.cert.pem
server-key = /etc/ocserv/server.key.pem
ca-cert = /etc/ocserv/ca.cert.pem
dh-params = /etc/ocserv/dh.pem
 
socket-file = /var/run/ocserv.socket
occtl-socket-file = /var/run/occtl.socket
pid-file = /var/run/ocserv.pid
user-profile = /etc/ocserv/profile.xml
run-as-user = nobody
select-group = All
select-group = Route
select-group = NoRoute
select-group = Scholar
auto-select-group = false
config-per-group = /etc/ocserv/group
cert-user-oid = 2.5.4.3
isolate-workers = false
max-clients = 192
max-same-clients = 192
keepalive = 32400
dpd = 300
mobile-dpd = 1800
#output-buffer = 1000
try-mtu-discovery = true
compression = true
no-compress-limit = 256
auth-timeout = 40 
idle-timeout = 1200
mobile-idle-timeout = 1200
cookie-timeout = 43200
persistent-cookies = true
deny-roaming = false
rekey-time = 43200
rekey-method = ssl
use-utmp = true
use-occtl = true
device = ocserv
predictable-ips = false
ping-leases = false
cisco-client-compat = true
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-RSA:-VERS-SSL3.0:-ARCFOUR-128"
ipv4-network = 192.168.8.0
ipv4-netmask = 255.255.255.0
dns = 192.168.8.1
 
EOF
cat >/etc/ocserv/profile.xml<<EOF
<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
 
 <ClientInitialization>
 <UseStartBeforeLogon UserControllable="false">false</UseStartBeforeLogon>
 <StrictCertificateTrust>false</StrictCertificateTrust>
 <RestrictPreferenceCaching>false</RestrictPreferenceCaching>
 <RestrictTunnelProtocols>false</RestrictTunnelProtocols>
 <BypassDownloader>true</BypassDownloader>
 <WindowsVPNEstablishment>AllowRemoteUsers</WindowsVPNEstablishment>
 <CertEnrollmentPin>pinAllowed</CertEnrollmentPin>
 <CertificateMatch>
 <KeyUsage>
 <MatchKey>Digital_Signature</MatchKey>
 </KeyUsage>
 <ExtendedKeyUsage>
 <ExtendedMatchKey>ClientAuth</ExtendedMatchKey>
 </ExtendedKeyUsage>
 </CertificateMatch>
 
 <BackupServerList>
             <HostAddress>$MyDomain</HostAddress>
 </BackupServerList>
 </ClientInitialization>
</AnyConnectProfile>
EOF

mkdir -p /etc/ocserv/template
cat >/etc/ocserv/template/ca.tmp<<EOF
cn = "$FILLIT1"
organization = "$FILLIT2"
serial = 1
expiration_days = 1825
ca
signing_key
cert_signing_key
crl_signing_key
EOF
openssl genrsa -out /etc/ocserv/template/ca.key.pem 2048
certtool --generate-self-signed --hash SHA256 --load-privkey /etc/ocserv/template/ca.key.pem --template /etc/ocserv/template/ca.tmp --outfile /etc/ocserv/ca.cert.pem
certtool --generate-dh-params --outfile /etc/ocserv/dh.pem

cat >/etc/ocserv/template/server.tmp<<EOF
cn = "$MyDomain" 
organization = "shui.azurewebsites.net" 
serial = 2
expiration_days = 1825
signing_key 
encryption_key
tls_www_server
EOF
openssl genrsa -out /etc/ocserv/server.key.pem 2048
certtool --generate-certificate --hash SHA256 --load-privkey /etc/ocserv/server.key.pem --load-ca-certificate /etc/ocserv/ca.cert.pem --load-ca-privkey /etc/ocserv/template/ca.key.pem --template /etc/ocserv/template/server.tmp --outfile /etc/ocserv/server.cert.pem
cat /etc/ocserv/ca.cert.pem >>/etc/ocserv/server.cert.pem
}

function login_ocserv()
{
[ $MyType == 'certificate' ] && {
cat >/etc/ocserv/template/user.tmp<<EOF
cn = "$FILLIT1"
unit = "$FILLIT2"
expiration_days = 1825
signing_key
tls_www_client
EOF
openssl genrsa -out /etc/ocserv/template/user.key.pem 2048
certtool --generate-certificate --hash SHA256 --load-privkey /etc/ocserv/template/user.key.pem --load-ca-certificate /etc/ocserv/ca.cert.pem --load-ca-privkey /etc/ocserv/template/ca.key.pem --template /etc/ocserv/template/user.tmp --outfile /etc/ocserv/template/user.cert.pem
cat /etc/ocserv/ca.cert.pem >>/etc/ocserv/template/user.cert.pem
openssl pkcs12 -export -inkey /etc/ocserv/template/user.key.pem -in /etc/ocserv/template/user.cert.pem -name "YHIblog" -certfile /etc/ocserv/ca.cert.pem -caname "$FILLIT1" -out /etc/ocserv/AnyConnect.p12 -passout pass:
[ -f /etc/ocserv/ocserv.conf ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "certificate".*/auth = "certificate"/g' /etc/ocserv/ocserv.conf
}
[ $MyType == 'password' ] && {
[ -f /etc/ocserv/ocpasswd ] && sed -i '/'${FILLIT1}':/d' /etc/ocserv/ocpasswd
echo -n "$FILLIT1:*:" >>/etc/ocserv/ocpasswd
openssl passwd "$FILLIT2" >>/etc/ocserv/ocpasswd
[ -f /etc/ocserv/ocserv.conf ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "plain.*/auth = "plain\[passwd=\/etc\/ocserv\/ocpasswd\]"/g' /etc/ocserv/ocserv.conf
}
}

function ask_ocserv()
{
Welcome
Ask_ocserv_port
Ask_ocserv_type
Ask_ocserv_password
pause
clear
}

function ins_dnsmasq()
{
apt-get install -y dnsmasq
cat >/etc/dnsmasq.conf<<EOF
except-interface=$ifname
dhcp-range=192.168.8.2,192.168.8.254,255.255.255.0,24h
dhcp-option-force=option:router,192.168.8.1
dhcp-option-force=option:dns-server,192.168.8.1
dhcp-option-force=option:netbios-ns,192.168.8.1
listen-address=127.0.0.1,192.168.8.1
no-resolv
bogus-priv
no-negcache
clear-on-reload
cache-size=81920
server=208.67.220.220#5353
EOF
bash /etc/init.d/dnsmasq restart
}

function ins_serverSpeeder()
{
[ $oVZ == 'n' ] && {
wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
[ $? -eq '0' ] && {
insNum="$(awk '/^SelectKernel;/{print NR}' /tmp/appex.sh)"
echo "sed -i '/^# Set acc inf/,\$d' /tmp/appex/install.sh" >/tmp/ins.tmp
echo "echo -e 'boot=y && addStartUpLink' >>/tmp/appex/install.sh" >>/tmp/ins.tmp
[ -f /tmp/ins.tmp ] && {
sed -i ''${insNum}'r /tmp/ins.tmp' /tmp/appex.sh
sed -i '/^pause;$/d' /tmp/appex.sh
sed -i '/serverSpeeder.sh status$/d' /tmp/appex.sh
}
bash /tmp/appex.sh install
}
}
}

function add_user()
{
[ "$(grep -c '^auth =' /etc/ocserv/ocserv.conf)" != '1' ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "plain.*/auth = "plain\[passwd=\/etc\/ocserv\/ocpasswd\]"/g' /etc/ocserv/ocserv.conf
MyType='password'
FILLIT1="$tmpUser"
FILLIT2="$tmpPass"
[ -n "$FILLIT1" ] && [ -n "$FILLIT2" ] && login_ocserv
(
echo "$FILLIT2"
sleep 1
echo "$FILLIT2")|ocpasswd -c /etc/ocserv/ocpasswd -g "All,Route,NoRoute,Scholar" $FILLIT1
bash /etc/init.d/ocserv restart
}

function del_user()
{
[ -f /etc/ocserv/ocpasswd ] && sed -i '/'${delUser}':/d' /etc/ocserv/ocpasswd
}

function ChangeType()
{
TheType="$(echo -n "$tmpType"|sed -r 's/(.*)/\L\1/')"
echo -n "$TheType" |grep -q '^cert'
[ $? -eq '0' ] && [ -f /etc/ocserv/ocserv.conf ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "certificate".*/auth = "certificate"/g' /etc/ocserv/ocserv.conf
echo -n "$TheType" |grep -q '^pass'
[ $? -eq '0' ] && [ -f /etc/ocserv/ocserv.conf ] && sed -i 's/^auth =/#auth =/g;s/^#auth = "plain.*/auth = "plain\[passwd=\/etc\/ocserv\/ocpasswd\]"/g' /etc/ocserv/ocserv.conf
[ -e /etc/init.d/ocserv ] && bash /etc/init.d/ocserv restart
}

function add_group()
{
mkdir -p /etc/ocserv/group
wget -c --no-check-certificate https://raw.githubusercontent.com/putiyeb/eazy-for-ss/master/ocservauto/All -O /etc/ocserv/group/All
wget -c --no-check-certificate https://raw.githubusercontent.com/putiyeb/eazy-for-ss/master/ocservauto/Route -O /etc/ocserv/group/Route
wget -c --no-check-certificate https://raw.githubusercontent.com/putiyeb/eazy-for-ss/master/ocservauto/NoRoute -O /etc/ocserv/group/NoRoute
wget -c --no-check-certificate https://raw.githubusercontent.com/putiyeb/eazy-for-ss/master/ocservauto/Scholar -O /etc/ocserv/group/Scholar
echo "no-route = $PublicIP/255.255.255.255" >> /etc/ocserv/group/All
echo "no-route = $PublicIP/255.255.255.255" >> /etc/ocserv/group/NoRoute
echo "no-route = $PublicIP/255.255.255.255" >> /etc/ocserv/group/Scholar
(
echo "$FILLIT2"
sleep 1
echo "$FILLIT2")|ocpasswd -c /etc/ocserv/ocpasswd -g "All,Route,NoRoute,Scholar" $FILLIT1
bash /etc/init.d/ocserv restart
}

function ins_all()
{
Welcome
ServerIP
ask_ocserv
ins_ocserv
login_ocserv
add_group
ins_dnsmasq
ins_serverSpeeder
SYSCONF
ins_Finish
}

function ins_Finish()
{
grep '^iptables' /etc/rc.local >/tmp/iptables.tmp
[ -f /tmp/iptables.tmp ] && bash /tmp/iptables.tmp
[ -e /etc/init.d/dnsmasq ] && bash /etc/init.d/dnsmasq restart
[ -e /etc/init.d/ocserv ] && bash /etc/init.d/ocserv restart
[ -e /etc/init.d/serverSpeeder ] && bash /etc/init.d/serverSpeeder restart
rm -rf /tmp/*.tmp
}

[ $# -eq '0' ] && ins_all
ins_it='0';
adduser='0';
delUser='0';
UseType='0';
tmpUser="";
tmpPass="";
tmpType="";
while [[ $# -ge 1 ]]; do
  case $1 in
    -i|ins|-ins|install|-install)
      shift
      ins_it='1'
      ;;
    -u|u|use|-use)
      shift
      UseType='1'
      tmpType="$1"
      shift
      ;;
    -a|a|-add|add)
      shift
      adduser='1'
      tmpUser="$1"
      shift
      tmpPass="$1"
      shift
      ;;
    -d|d|-del|del)
      shift
      delUser='1'
      tmpUser="$1"
      shift
      ;;
    *)
      echo -ne " Usage:\n\tbash $0\t\n"
      exit 1;
      ;;
    esac
  done

[ "$ins_it" == '1' ] && ins_all;
[ "$UseType" == '1' ] && [ -n "$tmpType" ] && ChangeType;
[ "$delUser" == '1' ] && [ -n "$tmpUser" ] && del_user;
[ "$adduser" == '1' ] && [ -n "$tmpUser" ] && [ -n "$tmpPass" ] && add_user;
