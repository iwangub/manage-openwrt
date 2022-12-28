#!/usr/bin/env python3

# importing modules
import argparse
import subprocess
import time
import pynetbox
import os

# create argparse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-V', '--openwrt-version', metavar='version', type=str, default=False,
                    help="openwrt version")
parser.add_argument('-IP', '--ip', metavar='ip', type=str, help='IP from your device')
#parser.add_argument('-ID', '--vigir-id', type=str, help='ID from your device, example:"0c01"')
parser.add_argument('-qmi', action='store_true',
                    help='Install qmi lte, this argument does not require a value, leave blank when not in use',
                    default=False)
parser.add_argument('-cleanup', action='store_true' ,help='adding passwd, remove our ssh keys and Correct test SSID to final one', default=False)

args = parser.parse_args()

# var for argparse arguments
version = args.openwrt_version
ip = args.ip
#id = args.vigir_id
qmi = args.qmi
cleanup = args.cleanup

ping = subprocess.call(["ping", "-c1", ip])


class CpuInfo:

    def __init__(self):
        self.microuter = b'GL.iNet microuter-N300'
        self.viwib = b'GL-MT300N-V2'
        self.viwib2 = b'GL.iNet GL-AR300M'
        self.vigir_pre_patch = b'Zbtlink ZBT-WG3526 (16M)'
        self.vigir_post_patch = b'ZBT-WG3526'
        self.cat_cpuinfo = subprocess.check_output(['ssh', f'root@{ip}', 'cat', '/proc/cpuinfo'])


    def device(self):
        if self.microuter in self.cat_cpuinfo:
            return "microuter"
        elif self.viwib in self.cat_cpuinfo:
            return "viwib"
        elif self.viwib2 in self.cat_cpuinfo:
            return "viwib2"
        elif self.vigir_pre_patch in self.cat_cpuinfo or self.vigir_post_patch in self.cat_cpuinfo:
            return "vigir"
        else:
            return False
##### Creating instance of the class CpuInfo()
cpuinfo = CpuInfo()
device = cpuinfo.device()
#####


class FirmwareUpdate():

    def __init__(self, ip, version):
        self.ip = ip
        self.device = cpuinfo.device()
        self.filename = {"microuter": "openwrt-" + version + "-ramips-mt76x8-glinet_microuter-n300-squashfs-sysupgrade.bin",
                    "viwib2": "openwrt-" + version + "-ath79-nand-glinet_gl-ar300m-nor-squashfs-sysupgrade.bin",
                    "viwib": "openwrt-" + version + "-ramips-mt76x8-glinet_gl-mt300n-v2-squashfs-sysupgrade.bin",
                    "vigir": "openwrt-" + version + "-ramips-mt7621-zbtlink_zbt-wg3526-16m-squashfs-sysupgrade.bin"}
        self.filename_difference = {"microuter": "/targets/ramips/mt76x8/",
                               "viwib2": "/targets/ath79/nand/",
                               "viwib": "/targets/ramips/mt76x8/",
                               "vigir": "/targets/ramips/mt7621/"}


    def prepare(self):
        download = f'http://downloads.openwrt.org/releases/{version}{self.filename_difference[self.device]}{self.filename[self.device]}'
        subprocess.call([f'ssh root@{ip} touch /etc/dropbear/authorized_keys'], shell=True)
        subprocess.call([f'cat ~/.ssh/id_rsa.pub | ssh root@{ip} "cat > /etc/dropbear/authorized_keys"'], shell=True)
        subprocess.call(['wget', '-c', '-6', '--tries=1', download])
        subprocess.call([f'ssh root@{ip} opkg update'], shell=True)
        subprocess.call([f'ssh root@{ip} opkg install openssh-sftp-server'], shell=True)
        subprocess.call([f'scp {self.filename[self.device]} root@{ip}:/tmp'], shell=True)


    def exe(self):

        def versionTest():
            vigir_version_check = subprocess.check_output(['ssh', f'root@{ip}', 'ls', '/tmp'])
            if b'ramips-mt7621-zbtlink_zbt-wg3526-16m-squashfs-sysupgrade.bin' in vigir_version_check:
                return True
            else:
                return False

        if cpuinfo.device() == "vigir" and versionTest() == True:
            print("Sysupgrade for VIGIR")
            subprocess.call([f'ssh root@{ip} sysupgrade -n -F /tmp/*.bin'], shell=True)
        elif cpuinfo.device() == "vigir" and versionTest() == False:
            print("No firmware update file in /tmp for VIGIR")
        elif cpuinfo.device() == "viwib" or "viwib2" or "microuter":
            print("Sysupgrade for VIWIB/Microuter")
            subprocess.call([f'ssh root@{ip} sysupgrade -n /tmp/*.bin'], shell=True)
        else:
            print("Something went wrong")


        print("Waiting 190 seconds for update. . .")
        time.sleep(190)
        print("Continue")
        if ping == 0:
            print(f"Your {self.device} successfully updated to openwrt-version-{version}!")
        #    return True
        else:
            print(f"Did not find updated device - debug / restart it")
        #    return False
##### Creating instance of the class FirmwareUpdate()
update = FirmwareUpdate(ip, version)
#####


class API():

    def __init__(self):
        self.url = "https://****"
        self.token = os.environ['NETBOXTOKEN']
        self.endpoint_dict = {
            "vpn-********0c00": 897,
            "vpn-**********00": 67,
            "vpn-**********00": 68,
            "vpn-**********00": 69
        }


    def getFreePrefix(self):
        def request(endpoint_id):
            nb = pynetbox.api(url=self.url, token=self.token)
            prefix_scope = nb.ipam.prefixes.get(endpoint_id)
            new_prefix = prefix_scope.available_prefixes.create({"prefix_length": 48})
            print(f'Prefix: {new_prefix}')
            return new_prefix
        for i in self.endpoint_dict.values():
            try:
                return request(i)
                break
            except:
                pass
        else:
            print("all endpoints failed...")
##### Create an instance of the API class and create variables that are needed globally in multiple classes.
API = API()
#
prefix_full = str(API.getFreePrefix())
prefix_id = f"0{prefix_full[10:13]}"
vpn_ip = prefix_full[:13]
wg_tunnel = f"{vpn_ip}::42/48"
#####


class WireguardHost():

    def __init__(self):
        self.prefix_full = prefix_full
        self.prefix_id = prefix_id
        self.endpoint_host_condition = self.prefix_full[10]
        self.vpn_endpoint = {

            #0c00-rainbow
            "c": "****:****:****:****:****:****:****:****",

            #0300-unknown
            "3": "unknown-address",

            #0500-unknown
            "5": "unknown-address",

            #0600-unknown
            "6": "unknown-address"
        }


    def createKeypair(self):
        # create public and privatekey
        # you must have wireguard installed on the computer // sudo apt install wireguard // sudo pacman -Syu wireguard
        subprocess.call([f"wg genkey | tee privatekey | wg pubkey > publickey"], shell=True)
        client_privatekey_bytes = subprocess.check_output([f'cat privatekey'], shell=True)
        client_publickey_bytes = subprocess.check_output([f'cat publickey'], shell=True)
        client_publickey_bytes = client_publickey_bytes[:-1]
        self.client_privatekey = client_privatekey_bytes.decode('utf-8')
        self.client_publickey = client_publickey_bytes.decode('utf-8')
        subprocess.call([f"rm privatekey"], shell=True)
        subprocess.call([f"rm publickey"], shell=True)
        print(f'your privatekey = {self.client_privatekey}your publickey = {self.client_publickey}')

        return self.client_publickey, self.client_privatekey


    def setPeer(self):
        # Configure VPN-Server
        print('connecting to wireguard server')
        subprocess.call([f'ssh root@{self.vpn_endpoint[str(self.endpoint_host_condition)]} wg set wg0 peer {self.client_publickey} allowed-ips ****:****:{self.prefix_id}::/48'], shell=True)
        print('wireguard settings complete')
        print('######')
        print('If the WG configuration has not yet been updated:')
        print(f'please enter the following command in the wireguard server({self.vpn_endpoint[str(self.endpoint_host_condition)]}): \n "wg set wg0 peer {client_publickey} allowed-ips ****:****:{self.prefix_id}::/48"')
        print('######')
##### Create an instance of the API class and create variables that are needed globally in multiple classes.
wgHost = WireguardHost()
#
publickkey_list = wgHost.createKeypair()
client_publickey = publickkey_list[0]
client_privatekey = publickkey_list[1]
#####


class Configuration:

    def __init__(self):
        self.device = device

        self.prefix_full = prefix_full
        self.prefix_id = prefix_id
        self.vpn_ip = vpn_ip
        self.wg_tunnel = wg_tunnel

        self.endpoint_host_condition = self.prefix_full[10]
        self.endpoint_host = {
            "c": "'vpn-************.****.ch'",
            "3": "'vpn-************.****.ch'",
            "5": "'vpn-************.****.ch'",
            "6": "'vpn-************.****.ch'"
        }


        self.vpn_endpoint_publickey = {
            "c": "*******",
            "3": "unknown-key",
            "5": "unknown-key",
            "6": "unknown-key"
        }


    def vigir(self):

       # vpn_endpoint_publickey = "*****"

        # Remove known_hosts error
        subprocess.run([f'ssh-keygen -R {ip}'], shell=True)

        cmds = [
            # Set IPv6 address on LAN
            f" uci set network.lan.ip6addr='{self.vpn_ip}:cafe::42/64'",

            # Do not announce ULA - we have GUA
            f" uci delete network.globals.ula_prefix",

            # Setup Router Advertisements / remove IPv4 dhcp
            f" uci set dhcp.lan.ra='server'",

            # We do stateless by default everywhere
            f" uci delete dhcp.lan.dhcpv6",

            # Fix DNS: make dnsmasq NOT use a resolv.conf
            # so that it only reads from our servers with DNS64 enabled
            f" uci set dhcp.@dnsmasq[0].noresolv='1'",

            # Fix DNS: make the OS use the locally provided DNS servers
            # otherwise the VPN tunnel cannot be established
            f" uci set dhcp.@dnsmasq[0].localuse='0'",

            # DNS upstream over VPN gives DNS64
            f" uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'",
            f" uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'",

            # Set Hostname
            f" uci set system.@system[0].hostname='vigir-{self.prefix_id}'",

            # Wifi configuration
            f" uci set wireless.radio0=wifi-device",
            f" uci set wireless.radio0.htmode='HT40'",
            f" uci set wireless.radio0.channel='6'",
            f" uci set wireless.radio0.country='CH'",
            f" uci set wireless.default_radio0.encryption='psk2'",
            f" uci set wireless.default_radio0.key='****'",
            f" uci set wireless.default_radio0.ssid='IPv6_everywhere_vigir-{self.prefix_id}'",
            f" uci set wireless.radio1.country='CH'",
            f" uci set wireless.default_radio1.encryption='psk2'",
            f" uci set wireless.default_radio1.key='****'",
            f" uci set wireless.default_radio1.ssid='IPv6_everywhere_vigir-{self.prefix_id}_5Ghz'",

            # Ensure it is not disabled
            f" uci delete wireless.radio0.disabled",
            f" uci delete wireless.radio1.disabled",

            # Create temporary IPV4 CLIENT on LAN
            # This way we get Internet/upstream from the LAN port
            # Can we do this via IPv6 instead?
            # this breaks if multiple vigir are setup, as we have fake / wrong
            # dhcp server configurations.
            # easy solution: using two different networks...
            # changed ipv4 from vigir 21 to 192.168.8.1

            f" uci commit",
            f" reboot"
        ]

        subprocess.call(["ssh", f"root@{ip}", "\n".join(cmds)])

        # wait for reboot
        print("waiting 60 seconds for reboot. . .")
        time.sleep(60)
        print("continue")

        cmds = [
            # update the source
            f" opkg update",
            f" opkg install luci-app-wireguard luci-proto-wireguard",

            # VPN / Wireguard
            f" uci set network.wg0=interface",
            f" uci set network.wg0.proto='wireguard'"
        ]

        subprocess.call(["ssh", f"root@{ip}", "\n".join(cmds)])

        cmds = [
            # continue VPN / Wireguard
            f" uci set network.wg0.private_key='{client_privatekey}'",
            f" uci set network.wg0.listen_port='51820'",
            f" uci set network.wg0.addresses='{self.wg_tunnel}'",
            f" uci add network wireguard_wg0",
            f" uci set network.@wireguard_wg0[0].persistent_keepalive='25'",
            f" uci set network.@wireguard_wg0[0].public_key='{self.vpn_endpoint_publickey[str(self.endpoint_host_condition)]}'",
            f" uci set network.@wireguard_wg0[0].description='IPv6VPN.****'",
            f" uci set network.@wireguard_wg0[0].allowed_ips='::/0'",
            f" uci set network.@wireguard_wg0[0].endpoint_host='{self.endpoint_host[str(self.endpoint_host_condition)]}'",
            f" uci set network.@wireguard_wg0[0].endpoint_port='51820'",
            f" uci set network.@wireguard_wg0[0].route_allowed_ips='1'",
            f" uci commit",
            " reboot"
        ]

        subprocess.call(["ssh", f"root@{ip}", "\n".join(cmds)])
        print("waiting 60 seconds. . .")
        time.sleep(60)

        cmds = [
            # Firewall configuration
            #if ! uci show firewall | grep "name='Allow-SSH'"; then
            f" uci add firewall rule",
            f" uci set firewall.@rule[-1].name='Allow-SSH'",
            f" uci set firewall.@rule[-1].src='wan'",
            f" uci set firewall.@rule[-1].dest='lan'",
            f" uci set firewall.@rule[-1].proto='tcp'",
            f" uci set firewall.@rule[-1].dest_port='22'",
            f" uci set firewall.@rule[-1].target='ACCEPT'",

            #fi
            ###
            # if ! uci show firewall | grep "name='Allow-HTTPS'"; then

            f" uci add firewall rule",
            f" uci set firewall.@rule[-1].name='Allow-HTTPS'",
            f" uci set firewall.@rule[-1].src='wan'",
            f" uci set firewall.@rule[-1].dest='lan'",
            f" uci set firewall.@rule[-1].proto='tcp'",
            f" uci set firewall.@rule[-1].dest_port='443'",
            f" uci set firewall.@rule[-1].target='ACCEPT'",

            #fi
            ###
            # if ! uci show firewall | grep "name='Allow-HTTP'"; then

            f" uci add firewall rule",
            f" uci set firewall.@rule[-1].name='Allow-HTTP'",
            f" uci set firewall.@rule[-1].src='wan'",
            f" uci set firewall.@rule[-1].dest='lan'",
            f" uci set firewall.@rule[-1].proto='tcp'",
            f" uci set firewall.@rule[-1].dest_port='80'",
            f" uci set firewall.@rule[-1].target='ACCEPT'",

            #fi

            f" uci set firewall.@zone[1].network='wan'",
            f" uci set firewall.@zone[1].network='wan6'",
            f" uci set firewall.@zone[1].network='wg0'",
            f" uci commit"
            f" reboot"
        ]

        subprocess.call(["ssh", f"root@{ip}", "\n".join(cmds)])
        print("waiting 60 seconds. . .")
        time.sleep(60)
        print(f'Your vigir has been successfully configured.')


    def viwib(self):
        print(f'Configuring {device}')

        subprocess.run(f'ssh-keygen -R {ip}', shell=True)

        cmds = [

            # 1. install packages
            # update the sources
            " opkg update",

            # install packages: wireguard + gui
            " opkg install luci-app-wireguard luci-proto-wireguard",

            # DO NOT Adjust LAN to be IPv6 only
            # uci delete network.lan.ipaddr
            # uci delete network.lan.netmask

            f" uci set network.lan.ip6addr='****:****:{self.vpn_ip}:****::42/64'",

            # Do not announce ULA - we have GUA
            " uci delete network.globals.ula_prefix",

            # Setup Router Advertisements / DO NOT remove IPv4 dhcp
            " uci set dhcp.lan.ra='server'",
            # uci set dhcp.lan.dynamicdhcp='0'
            # uci delete dhcp.@dnsmasq[0].authoritative
            # uci delete dhcp.lan.start
            # uci delete dhcp.lan.limit
            # uci delete dhcp.lan.leasetime

            # We do stateless by default everywhere, however we can keep dhcp on ...
            # uci delete dhcp.lan.dhcpv6

            # Fix DNS: make dnsmasq NOT use a resolv.conf
            # so that it only reads from our servers with DNS64 enabled
            " uci set dhcp.@dnsmasq[0].noresolv='1'",

            # Fix DNS: make the OS use the locally provided DNS servers
            # otherwise the VPN tunnel cannot be established
            " uci set dhcp.@dnsmasq[0].localuse='0'",

            # DNS upstream over VPN gives DNS64
            " uci delete dhcp.@dnsmasq[0].server",
            " uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'",
            " uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'",

            f" uci set system.@system[0].hostname='viwib-{self.prefix_id}'",

            # wifi ip address
            # uci set network.wifi=interface
            # uci set network.wifi.proto='static'
            # uci set network.wifi.ip6addr='${my_wifi_ip}/64'
            # Wifi configuration
            " uci set wireless.radio0=wifi-device",
            " uci set wireless.radio0.htmode='HT40'",
            " uci set wireless.radio0.country='CH'",
            " uci set wireless.radio0.channel='6'",
            " uci set wireless.default_radio0.encryption='psk2'",
            " uci set wireless.default_radio0.key='****'",
            f" uci set wireless.default_radio0.ssid='IPv6 everywhere viwib-{self.prefix_id}'",

            # Ensure it is not disabled
            " uci delete wireless.radio0.disabled",

            " uci commit",

            # VPN / Wireguard
            " uci set network.wg0=interface",
            " uci set network.wg0.proto='wireguard'",
            f" uci set network.wg0.private_key='{client_privatekey}'",
            " uci set network.wg0.listen_port='51820'",
            f" uci set network.wg0.addresses='****:****:{self.vpn_ip}::42/48'",

            # if ! uci get network.@wireguard_wg0[0]; then
            " uci add network wireguard_wg0",
            # fi

            " uci set network.@wireguard_wg0[0]=wireguard_wg0",
            " uci set network.@wireguard_wg0[0].persistent_keepalive='25'",
            f" uci set network.@wireguard_wg0[0].public_key='{self.vpn_endpoint_publickey[str(self.endpoint_host_condition)]}'",
            " uci set network.@wireguard_wg0[0].description='IPv6VPN.****'",
            " uci set network.@wireguard_wg0[0].allowed_ips='::/0'",
            f" uci set network.@wireguard_wg0[0].endpoint_host='{self.endpoint_host[str(self.endpoint_host_condition)]}'",
            " uci set network.@wireguard_wg0[0].endpoint_port='51820'",
            " uci set network.@wireguard_wg0[0].route_allowed_ips='1'",

            # Firewall configuration
            # if ! uci show firewall | grep "name='Allow-SSH'"; then
            " uci add firewall rule",
            " uci set firewall.@rule[-1].name='Allow-SSH'",
            " uci set firewall.@rule[-1].src='wan'",
            " uci set firewall.@rule[-1].dest='lan'",
            " uci set firewall.@rule[-1].proto='tcp'",
            " uci set firewall.@rule[-1].dest_port='22'",
            " uci set firewall.@rule[-1].target='ACCEPT'",
            # fi

            # if ! uci show firewall | grep "name='Allow-HTTPS'"; then
            " uci add firewall rule",
            " uci set firewall.@rule[-1].name='Allow-HTTPS'",
            " uci set firewall.@rule[-1].src='wan'",
            " uci set firewall.@rule[-1].dest='lan'",
            " uci set firewall.@rule[-1].proto='tcp'",
            " uci set firewall.@rule[-1].dest_port='443'",
            " uci set firewall.@rule[-1].target='ACCEPT'",
            # fi

            # if ! uci show firewall | grep "name='Allow-HTTP'"; then
            " uci add firewall rule",
            " uci set firewall.@rule[-1].name='Allow-HTTP'",
            " uci set firewall.@rule[-1].src='wan'",
            " uci set firewall.@rule[-1].dest='lan'",
            " uci set firewall.@rule[-1].proto='tcp'",
            " uci set firewall.@rule[-1].dest_port='80'",
            " uci set firewall.@rule[-1].target='ACCEPT'",
            # fi

            # if ! uci show firewall | grep "name='Allow-SSH-in'"; then
            " uci add firewall rule",
            " uci set firewall.@rule[-1].name='Allow-SSH-in'",
            " uci set firewall.@rule[-1].src='wan'",
            " uci set firewall.@rule[-1].proto='tcp'",
            " uci set firewall.@rule[-1].dest_port='22'",
            " uci set firewall.@rule[-1].target='ACCEPT'",
            # fi

            # Add interfaces to the right network zone
            " uci set firewall.@zone[1].network='wan wan6 wg0'",
            " uci commit",
            " reboot"
        ]

        subprocess.call(["ssh", f"root@{ip}", "\n".join(cmds)])

        print("waiting 60 seconds for reboot. . .")
        time.sleep(60)

        print(f'Your {device} has been successfully configured.')


    def viwib2(self):
        print(f'Configuring {device}')

        subprocess.run(f'ssh-keygen -R {ip}', shell=True)


        cmds = [

            # 1. install packages
            # update the sources
            " opkg update",

            # install packages: wireguard + gui
            " opkg install luci-app-wireguard luci-proto-wireguard",

            # DO NOT Adjust LAN to be IPv6 only
            # uci delete network.lan.ipaddr
            # uci delete network.lan.netmask

            f" uci set network.lan.ip6addr='****:****:{self.vpn_ip}:****::42/64'",

            # Do not announce ULA - we have GUA
            " uci delete network.globals.ula_prefix",

            # Setup Router Advertisements / DO NOT remove IPv4 dhcp
            " uci set dhcp.lan.ra='server'",
            # uci set dhcp.lan.dynamicdhcp='0'
            # uci delete dhcp.@dnsmasq[0].authoritative
            # uci delete dhcp.lan.start
            # uci delete dhcp.lan.limit
            # uci delete dhcp.lan.leasetime

            # We do stateless by default everywhere, however we can keep dhcp on ...
            # uci delete dhcp.lan.dhcpv6

            # Fix DNS: make dnsmasq NOT use a resolv.conf
            # so that it only reads from our servers with DNS64 enabled
            " uci set dhcp.@dnsmasq[0].noresolv='1'",

            # Fix DNS: make the OS use the locally provided DNS servers
            # otherwise the VPN tunnel cannot be established
            " uci set dhcp.@dnsmasq[0].localuse='0'",

            # DNS upstream over VPN gives DNS64
            " uci delete dhcp.@dnsmasq[0].server",
            " uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'",
            " uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'",

            f" uci set system.@system[0].hostname='viwib2-{self.prefix_id}'",

            # wifi ip address
            # uci set network.wifi=interface
            # uci set network.wifi.proto='static'
            # uci set network.wifi.ip6addr='${my_wifi_ip}/64'
            # Wifi configuration
            " uci set wireless.radio0=wifi-device",
            " uci set wireless.radio0.htmode='HT40'",
            " uci set wireless.radio0.country='CH'",
            " uci set wireless.radio0.channel='6'",
            " uci set wireless.default_radio0.encryption='psk2'",
            " uci set wireless.default_radio0.key='****'",
            f" uci set wireless.default_radio0.ssid='IPv6 everywhere viwib2-{self.prefix_id}'",

            # Ensure it is not disabled
            " uci delete wireless.radio0.disabled",

            " uci commit",

            # VPN / Wireguard
            " uci set network.wg0=interface",
            " uci set network.wg0.proto='wireguard'",
            f" uci set network.wg0.private_key='{client_privatekey}'",
            " uci set network.wg0.listen_port='51820'",
            f" uci set network.wg0.addresses='{self.wg_tunnel}'",

            # if ! uci get network.@wireguard_wg0[0]; then
            " uci add network wireguard_wg0",
            # fi

            " uci set network.@wireguard_wg0[0]=wireguard_wg0",
            " uci set network.@wireguard_wg0[0].persistent_keepalive='25'",
            f" uci set network.@wireguard_wg0[0].public_key='{self.vpn_endpoint_publickey[str(self.endpoint_host_condition)]}'",
            " uci set network.@wireguard_wg0[0].description='IPv6VPN.****'",
            " uci set network.@wireguard_wg0[0].allowed_ips='::/0'",
            f" uci set network.@wireguard_wg0[0].endpoint_host='{self.endpoint_host[str(self.endpoint_host_condition)]}'",
            " uci set network.@wireguard_wg0[0].endpoint_port='51820'",
            " uci set network.@wireguard_wg0[0].route_allowed_ips='1'",

            # Firewall configuration
            # if ! uci show firewall | grep "name='Allow-SSH'"; then
            " uci add firewall rule",
            " uci set firewall.@rule[-1].name='Allow-SSH'",
            " uci set firewall.@rule[-1].src='wan'",
            " uci set firewall.@rule[-1].dest='lan'",
            " uci set firewall.@rule[-1].proto='tcp'",
            " uci set firewall.@rule[-1].dest_port='22'",
            " uci set firewall.@rule[-1].target='ACCEPT'",
            # fi

            # if ! uci show firewall | grep "name='Allow-HTTPS'"; then
            " uci add firewall rule",
            " uci set firewall.@rule[-1].name='Allow-HTTPS'",
            " uci set firewall.@rule[-1].src='wan'",
            " uci set firewall.@rule[-1].dest='lan'",
            " uci set firewall.@rule[-1].proto='tcp'",
            " uci set firewall.@rule[-1].dest_port='443'",
            " uci set firewall.@rule[-1].target='ACCEPT'",
            # fi

            # if ! uci show firewall | grep "name='Allow-HTTP'"; then
            " uci add firewall rule",
            " uci set firewall.@rule[-1].name='Allow-HTTP'",
            " uci set firewall.@rule[-1].src='wan'",
            " uci set firewall.@rule[-1].dest='lan'",
            " uci set firewall.@rule[-1].proto='tcp'",
            " uci set firewall.@rule[-1].dest_port='80'",
            " uci set firewall.@rule[-1].target='ACCEPT'",
            # fi

            # if ! uci show firewall | grep "name='Allow-SSH-in'"; then
            " uci add firewall rule",
            " uci set firewall.@rule[-1].name='Allow-SSH-in'",
            " uci set firewall.@rule[-1].src='wan'",
            " uci set firewall.@rule[-1].proto='tcp'",
            " uci set firewall.@rule[-1].dest_port='22'",
            " uci set firewall.@rule[-1].target='ACCEPT'",
            # fi

            # Add interfaces to the right network zone
            " uci set firewall.@zone[1].network='wan wan6 wg0'",
            " uci commit",
            " reboot"
        ]

        subprocess.call(["ssh", f"root@{ip}", "\n".join(cmds)])

        print("waiting 60 seconds for reboot. . .")
        time.sleep(60)
        print(f'Your {device} has been successfully configured.')


    def microuter(self):
        print('Configuring Microuter')


    def qmi(self):
        print('Configuration QMI-LTE-Modem')
        uci_command = []

        uci_command.append(f"opkg update")
        uci_command.append(f"opkg install libustream-openssl ca-bundle ca-certificates")
        uci_command.append(f"opkg install kmod-usb-net-qmi-wwan uqmi luci-proto-qmi")

        for i in uci_command:
            subprocess.call([f'ssh root@{ip} {i}'], shell=True)

        uci_command = []
        # Create Interface
        uci_command.append(f"uci set network.lte=interface")
        uci_command.append(f"uci set network.lte.device='/dev/cdc-wdm0'")
        uci_command.append(f"uci set network.lte.proto='qmi'")
        uci_command.append(f"uci set network.lte.apn='internet'")
        uci_command.append(f"uci set network.lte.auth='both'")
        uci_command.append(f"uci set network.lte.modes='lte'")
        uci_command.append(f"uci set network.lte.pdptype='ipv4'")
        uci_command.append(f"uci set network.lte.username='any'")
        uci_command.append(f"uci set network.lte.password='any'")

        for i in uci_command:
            subprocess.call([f'ssh root@{ip} {i}'], shell=True)
        uci_command = []

        # add to correct firewall zone
        # dont work right, but the current network is wg0
        """
        current_networks = subprocess.check_output([f'uci get firewall.@zone[1].network'], shell=True)
        print(current_networks)
        """
        subprocess.call(["ssh", f"root@{ip}", "uci", "set", "firewall.@zone[1].network='wg0 lte'"])
        subprocess.call([f'ssh root@{ip} uci commit'], shell=True)
        subprocess.call([f'ssh root@{ip} reboot'], shell=True)
        print(f'your {self.device} has been successfully qmi-lte configured.')
##### Creating instance of the class Configuration()
configuration = Configuration()
#####


class Cleanup:

    def viwib(self):
        print(f'Cleaning up {device}')

        root_password_bytes = subprocess.check_output(["pwgen", "-1", "32"])
        root_password = root_password_bytes.decode('utf-8')
        print(f'Root Password: {root_password}')

        cmds = [
            f" uci set wireless.default_radio0.ssid='IPv6 everywhere'",
            f" uci commit",
            f" rm -f /etc/dropbear/authorized_keys",
            f' printf "{root_password}{root_password}" | passwd',
            ' reboot'
        ]

        subprocess.call([f'printf "{root_password}{root_password}" | pass insert openwrt/{device}/{device}-{id}'], shell=True)
        subprocess.run([f'pass', 'git', 'push'], check=True)

        subprocess.call(["ssh", f"root@{ip}", "\n".join(cmds)])

        if ping == 0:
            print(f'cleanup for {device} complete')
        else:
            raise Exception(f'can not find, {device}')


    def viwib2(self):
        print(f'Cleaning up {device}')

        root_password_bytes = subprocess.check_output(["pwgen", "-1", "32"])
        root_password = root_password_bytes.decode('utf-8')
        print(f'Root Password: {root_password}')

        subprocess.call([f'printf "{root_password}{root_password}" | pass insert openwrt/{device}/{device}-{id}'],
                        shell=True)
        subprocess.run([f'pass', 'git', 'push'], check=True)

        cmds = [
            f" uci set wireless.default_radio0.ssid='IPv6 everywhere'",
            f" uci commit",
            f" rm -f /etc/dropbear/authorized_keys",
            f' printf "{root_password}{root_password}" | passwd',
            ' reboot'
        ]
        subprocess.call(["ssh", f"root@{ip}", "\n".join(cmds)])
        time.sleep(60)
        print('Waiting 60 seconds for reboot. . .')

        if ping == 0:
            print(f'cleanup for {device} complete')
        else:
            raise Exception(f'can not find, {device}')


    def vigir(self):
        print(f'Cleaning up {device}')

        root_password_bytes = subprocess.check_output(["pwgen", "-1", "32"])
        root_password = root_password_bytes.decode('utf-8')
        print(f'Root Password: {root_password}')
        subprocess.call([f'printf "{root_password}{root_password}" | pass insert openwrt/{device}/{device}-{id}'], shell=True)
        subprocess.run([f'pass', 'git', 'push'], check=True)

        cmds = [
            f' rm -f /etc/dropbear/authorized_keys',
            f' printf "{root_password}{root_password}" | passwd',
            f' reboot'
        ]
        subprocess.call(["ssh", f"root@{ip}", "\n".join(cmds)])
        time.sleep(60)
        print('Waiting 60 seconds for reboot. . .')
        if ping == 0:
            print(f'cleanup for {device} complete')
        else:
            raise Exception(f'can not find, {device}')
##### Creating instance of the class Cleanup()
clean = Cleanup()
#####


##### Starting the Programm
if __name__ == '__main__':
    if ping == 0:
        print('starting .... ')

        if isinstance(version, str):
            update.prepare()
            update.exe()
        else:
            print(f'no firmware update')

        if device in ['vigir', 'viwib', 'viwib2', 'microuter']:
            wgHost.setPeer()
            configuration.__getattribute__(cpuinfo.device())()
        else:
            raise Exception(f'Unsupported device, {device}')

        if qmi:
            configuration.qmi()
        else:
            print(f'no qmi-lte config')

        if cleanup:
            clean.__getattribute__(cpuinfo.device())()
        else:
            print(f'no cleanup')
    else:
        raise Exception('The device is not reachable')