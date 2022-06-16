#!/usr/bin/env python3

# importing modules
import argparse
import subprocess
import time

# create argparse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-V', '--openwrt-version', metavar='version', type=str, default="21.02.1",
                    help="openwrt version")
parser.add_argument('-IP', '--ip', metavar='ip', type=str, help='IP from your device')
parser.add_argument('-ID', '--vigir-id', type=str, help='ID from your device, example:"0c01"')
parser.add_argument('-qmi', action='store_true',
                    help='Install qmi lte, this argument does not require a value, leave blank when not in use',
                    default=False)
args = parser.parse_args()

# var for argparse arguments
version = args.openwrt_version
ip = args.ip
vigir_id = args.vigir_id
qmi = args.qmi

ping = subprocess.call(["ping", "-c1", ip])


class CpuInfo:
    def __init__(self):
        self.ip = ip
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
#####


class FirmwareUpdate:
    def __init__(self, ip, version):
        self.ip = ip
        self.version = version
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


        print("Waiting 180 seconds for update. . .")
        time.sleep(190)
        print("Continue")
        if ping == 0:
            print(f"Your {self.device} successfully updated to openwrt-version-{version}!")
        #    return True
        else:
            print(f"Did not find updated device - debug / restart it")
        #    return False
##### Creating instance of the class Firmwareupdate()
update = FirmwareUpdate(ip, version)
#####


class Configuration:
    def __init__(self):
        self.ip = ip
        self.device = cpuinfo.device()
        self.vigir_id = vigir_id

    def vigir(self):
        vigir_id_short = vigir_id[1:]
        vpn_endpoint_publickey = "*****"
        uci_command = []

        # Remove known_hosts error
        subprocess.call([f'ssh-keygen -R {ip}'], shell=True)

        # Set IPv6 address on LAN
        uci_command.append(f"uci set network.lan.ip6addr='****:****:{vigir_id_short}:****::**/64'")

        # Do not announce ULA - we have GUA
        uci_command.append(f"uci delete network.globals.ula_prefix")

        # Setup Router Advertisements / remove IPv4 dhcp
        uci_command.append(f"uci set dhcp.lan.ra='server'")

        # We do stateless by default everywhere
        uci_command.append(f"uci delete dhcp.lan.dhcpv6")

        # Fix DNS: make dnsmasq NOT use a resolv.conf
        # so that it only reads from our servers with DNS64 enabled
        uci_command.append(f"uci set dhcp.@dnsmasq[0].noresolv='1'")

        # Fix DNS: make the OS use the locally provided DNS servers
        # otherwise the VPN tunnel cannot be established
        uci_command.append(f"uci set dhcp.@dnsmasq[0].localuse='0'")

        # DNS upstream over VPN gives DNS64
        uci_command.append(f"uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'")
        uci_command.append(f"uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'")

        # Set Hostname
        uci_command.append(f"uci set system.@system[0].hostname='vigir-{vigir_id}'")

        # Wifi configuration
        uci_command.append(f"uci set wireless.radio0=wifi-device")
        uci_command.append(f"uci set wireless.radio0.htmode='HT40'")
        uci_command.append(f"uci set wireless.radio0.channel='6'")
        uci_command.append(f"uci set wireless.radio0.country='CH'")
        uci_command.append(f"uci set wireless.default_radio0.encryption='psk2'")
        uci_command.append(f"uci set wireless.default_radio0.key='*****'")
        uci_command.append(f"uci set wireless.default_radio0.ssid='****-{vigir_id}'")
        uci_command.append(f"uci set wireless.radio1.country='CH'")
        uci_command.append(f"uci set wireless.default_radio1.encryption='psk2'")
        uci_command.append(f"uci set wireless.default_radio1.key='******'")
        uci_command.append(f"uci set wireless.default_radio1.ssid='*****-{vigir_id}_5Ghz'")

        # Ensure it is not disabled
        uci_command.append(f"uci delete wireless.radio0.disabled")
        uci_command.append(f"uci delete wireless.radio1.disabled")
        # Create temporary IPV4 CLIENT on LAN
        # This way we get Internet/upstream from the LAN port
        # Can we do this via IPv6 instead?
        # this breaks if multiple vigir are setup, as we have fake / wrong
        # dhcp server configurations.
        # easy solution: using two different networks...
        # changed ipv4 from vigir 21 to 192.168.8.1

        uci_command.append(f"uci commit")
        uci_command.append(f"reboot")

        for i in uci_command:
            subprocess.call([f"ssh root@{ip} {i}"], shell=True)
        uci_command = []

        # wait for reboot
        print("waiting 60 seconds for reboot. . .")
        time.sleep(60)
        print("continue")

        # update the source
        uci_command.append(f"opkg update")
        uci_command.append(f"opkg install luci-app-wireguard luci-proto-wireguard")

        # VPN / Wireguard
        uci_command.append(f"uci set network.wg0=interface")
        uci_command.append(f"uci set network.wg0.proto='wireguard'")

        for i in uci_command:
            subprocess.call([f"ssh root@{ip} {i}"], shell=True)
        uci_command = []

        # create public and privatekey
        # you must have wireguard installed on the computer // sudo apt install wireguard // sudo pacman -Syu wireguard
        subprocess.call([f"wg genkey | tee privatekey | wg pubkey > publickey"], shell=True)
        client_privatekey_bytes = subprocess.check_output([f'cat privatekey'], shell=True)
        client_publickey_bytes = subprocess.check_output([f'cat publickey'], shell=True)
        client_publickey_bytes = client_publickey_bytes[:-1]
        client_privatekey = client_privatekey_bytes.decode('utf-8')
        client_publickey = client_publickey_bytes.decode('utf-8')
        subprocess.call([f"rm privatekey"], shell=True)
        subprocess.call([f"rm publickey"], shell=True)
        print(f'your privatekey = {client_privatekey}your publickey = {client_publickey}')

        #continue VPN / Wireguard
        uci_command.append(f"uci set network.wg0.private_key='{client_privatekey}'")
        uci_command.append(f"uci set network.wg0.listen_port='51820'")
        uci_command.append(f"uci set network.wg0.addresses='****:****:{vigir_id_short}::42/48'")

        # continue VPN / Wireguard
        uci_command.append(f"uci add network wireguard_wg0")
        uci_command.append(f"uci set network.@wireguard_wg0[0].persistent_keepalive='25'")
        uci_command.append(f"uci set network.@wireguard_wg0[0].public_key='{vpn_endpoint_publickey}'")
        uci_command.append(f"uci set network.@wireguard_wg0[0].description='******'")
        uci_command.append(f"uci set network.@wireguard_wg0[0].allowed_ips='::/0'")
        uci_command.append(f"uci set network.@wireguard_wg0[0].endpoint_host='vpn-*****'")
        uci_command.append(f"uci set network.@wireguard_wg0[0].endpoint_port='51820'")
        uci_command.append(f"uci set network.@wireguard_wg0[0].route_allowed_ips='1'")


        for i in uci_command:
            subprocess.call([f"ssh root@{ip} {i}"], shell=True)
        uci_command = []

        ### changed ipv4 from vigir 21 to 192.168.8.1
        # Configure VPN-Server
        print('connecting to wireguard server')
        wg_server = '****:****:*:*:****:****:****:****'
        subprocess.call([f'ssh root@{wg_server} wg set wg0 peer {client_publickey} allowed-ips ****:****:{vigir_id_short}::/48'], shell=True)
        print('wireguard settings complete')
        ###

        # Firewall configuration
        #if ! uci show firewall | grep "name='Allow-SSH'"; then
        uci_command.append(f"uci add firewall rule")
        uci_command.append(f"uci set firewall.@rule[-1].name='Allow-SSH'")
        uci_command.append(f"uci set firewall.@rule[-1].src='wan'")
        uci_command.append(f"uci set firewall.@rule[-1].dest='lan'")
        uci_command.append(f"uci set firewall.@rule[-1].proto='tcp'")
        uci_command.append(f"uci set firewall.@rule[-1].dest_port='22'")
        uci_command.append(f"uci set firewall.@rule[-1].target='ACCEPT'")
        #fi
        #####
        #if ! uci show firewall | grep "name='Allow-HTTPS'"; then
        uci_command.append(f"uci add firewall rule")
        uci_command.append(f"uci set firewall.@rule[-1].name='Allow-HTTPS'")
        uci_command.append(f"uci set firewall.@rule[-1].src='wan'")
        uci_command.append(f"uci set firewall.@rule[-1].dest='lan'")
        uci_command.append(f"uci set firewall.@rule[-1].proto='tcp'")
        uci_command.append(f"uci set firewall.@rule[-1].dest_port='443'")
        uci_command.append(f"uci set firewall.@rule[-1].target='ACCEPT'")
        #fi
        #####
        #if ! uci show firewall | grep "name='Allow-HTTP'"; then
        uci_command.append(f"uci add firewall rule")
        uci_command.append(f"uci set firewall.@rule[-1].name='Allow-HTTP'")
        uci_command.append(f"uci set firewall.@rule[-1].src='wan'")
        uci_command.append(f"uci set firewall.@rule[-1].dest='lan'")
        uci_command.append(f"uci set firewall.@rule[-1].proto='tcp'")
        uci_command.append(f"uci set firewall.@rule[-1].dest_port='80'")
        uci_command.append(f"uci set firewall.@rule[-1].target='ACCEPT'")
        #fi

        uci_command.append(f"uci set firewall.@zone[1].network='wan'")
        uci_command.append(f"uci set firewall.@zone[1].network='wan6'")
        uci_command.append(f"uci set firewall.@zone[1].network='wg0'")
        uci_command.append(f"uci commit")
        uci_command.append(f"reboot")

        for i in uci_command:
            subprocess.call([f"ssh root@{ip} {i}"], shell=True)
        uci_command = []

        print("waiting 60 seconds. . .")
        time.sleep(60)
        print(f'your vigir has been successfully configured.')
        print('######')
        print('If the WG configuration has not yet been updated:')
        print(f'please enter the following command in the wireguard server(****:****:*:*:****:****:****:****): \n "wg set wg0 peer {client_publickey} allowed-ips ****:****:{vigir_id_short}::/48"')

    def viwib(self):
        print('Configuring VIWIB')

    def viwib2(self):
        print('Configuring VIWIB2')

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
        # doesnt work right, but the current network is wg0
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


##### Starting the Programm
if __name__ == '__main__':
    if ping == 0:
        print('starting .... ')
        update.prepare()
        update.exe()


        if cpuinfo.device() == 'vigir':
            configuration.vigir()
        elif cpuinfo.device() == 'viwib':
            configuration.viwib()
        elif cpuinfo.device() == 'viwib2':
            configuration.viwib2()
        elif cpuinfo.device() == 'microuter':
            configuration.microuter()

        #configuration = f'configuration.{cpuinfo.device()}()'
        #print(configuration)


        if qmi != False:
            configuration.qmi()
        else:
            print(f'no qmi-lte config')
        #########

        print('done')
    else:
        print('The device is not reachable')
#####

