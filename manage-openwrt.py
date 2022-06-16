#!/usr/bin/env python3
# This script will flash and configure your Microuter, VIWIB, VIWIB2 or VIGIR with the desired version

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
parser.add_argument('-qmi', action='store_true', help='Install qmi lte, this argument does not require a value, leave blank when not in use', default=False)
args = parser.parse_args()

# var for argparse arguments
version = args.openwrt_version
ip = args.ip
vigir_id = args.vigir_id
qmi = args.qmi


# var for ping
ping = subprocess.call(["ping", "-c", "1", ip])

# store the output from /proc/cpuinfo
cpuinfo_stored_microuter = b'GL.iNet microuter-N300'
cpuinfo_stored_viwib = b'GL-MT300N-V2'
cpuinfo_stored_viwib2 = b'GL.iNet GL-AR300M'
cpuinfo_stored_vigir_pre_patch = b'Zbtlink ZBT-WG3526 (16M)'
cpuinfo_stored_vigir_post_patch = b'ZBT-WG3526'

# var for cpuinfo storing
cat_cpuinfo = subprocess.check_output(['ssh', f'root@{ip}', 'cat', '/proc/cpuinfo'])


# check the device which cpuinfo is stored
def get_cpuinfo_func():
    if cpuinfo_stored_microuter in cat_cpuinfo:
        return "microuter"
    elif cpuinfo_stored_viwib in cat_cpuinfo:
        return "viwib"
    elif cpuinfo_stored_viwib2 in cat_cpuinfo:
        return "viwib2"
    elif cpuinfo_stored_vigir_pre_patch in cat_cpuinfo or cpuinfo_stored_vigir_post_patch in cat_cpuinfo:
        return "vigir"
    else:
        return False

# firmware update
def firmware_update(device):
    # dictionary
    filename = {"microuter": "openwrt-" + version + "-ramips-mt76x8-glinet_microuter-n300-squashfs-sysupgrade.bin",
                "viwib2": "openwrt-" + version + "-ath79-nand-glinet_gl-ar300m-nor-squashfs-sysupgrade.bin",
                "viwib": "openwrt-" + version + "-ramips-mt76x8-glinet_gl-mt300n-v2-squashfs-sysupgrade.bin",
                "vigir": "openwrt-" + version + "-ramips-mt7621-zbtlink_zbt-wg3526-16m-squashfs-sysupgrade.bin"}

    filename_difference = {"microuter": "/targets/ramips/mt76x8/",
                           "viwib2": "/targets/ath79/nand/",
                           "viwib": "/targets/ramips/mt76x8/",
                           "vigir": "/targets/ramips/mt7621/"}


    ### You only need this config for the stock version ###
    # just for connecting, 'ssh -oHostKeyAlgorithms=+ssh-rsa root@192.168.8.1' works
    # but for the scp command you need to edit the ~/.ssh/config file
    # var for ~/.ssh/config
    #ssh_config = f'"Host {ip}\nHostName {ip}\nIdentityFile ~/.ssh/id_rsa\nIdentitiesOnly yes\nPubkeyAcceptedAlgorithms +ssh-rsa\nHostKeyAlgorithms +ssh-rsa"'
    # create the ~/.ssh/config for the negotiate error
    #subprocess.call([f'echo {ssh_config} >> ~/.ssh/config'], shell=True)

    # what about removing the settings at the end?
    # subprocess.call(['rm ~/.ssh/config'], shell=True)

    # executing commands for firmware update
    def execute(ip_, version_, filename_, filename_difference):
        # this removes known_hosts (solution for the fingerprint error)
        subprocess.call(['ssh-keygen', '-R', ip_])


        # drop the public key on the device
        subprocess.call([f'ssh root@{ip_} touch /etc/dropbear/authorized_keys'], shell=True)
        subprocess.call([f'cat ~/.ssh/id_rsa.pub | ssh root@{ip} "cat > /etc/dropbear/authorized_keys"'], shell=True)
        ### the old config gets deleted
        # non zero error if 'ls /etc/dropbear/authorized_keys or | grep authorized_keys


        # download the firmware update
        download = f'http://downloads.openwrt.org/releases/{version_}{filename_difference}{filename_}'
        subprocess.call(['wget', '-c', '-6', '--tries=1', download])


        #install sftp-server
        #untested on stock vigirs
        subprocess.call([f'ssh root@{ip_} opkg update'], shell=True)
        subprocess.call([f'ssh root@{ip_} opkg install openssh-sftp-server'], shell=True)


        # copy the file to the device
        subprocess.call([f'scp {filename_} root@{ip_}:/tmp'], shell=True)

        # version check so nothing wrong goes thru -F command
        def vigir_version_test():
            vigir_version_check = subprocess.check_output(['ssh', f'root@{ip}', 'ls', '/tmp'])
            if b'ramips-mt7621-zbtlink_zbt-wg3526-16m-squashfs-sysupgrade.bin' in vigir_version_check:
                return True
            else:
                return False

        # execute the installer
        # different sysupgrade command for the VIGIR
        if get_cpuinfo_func() == "vigir" and vigir_version_test() == True:
            print("Sysupgrade for VIGIR")
            subprocess.call([f'ssh root@{ip} sysupgrade -n -F /tmp/*.bin'], shell=True)
        elif get_cpuinfo_func() == "vigir" and vigir_version_test() == False:
            print("No firmware update file in /tmp for VIGIR")
        elif get_cpuinfo_func() == "viwib" or "viwib2" or "microuter":
            print("Sysupgrade for VIWIB/Microuter")
            subprocess.call([f'ssh root@{ip} sysupgrade -n /tmp/*.bin'], shell=True)
        else:
            print("Something went wrong")

        # wait for reboot
        print("Waiting 180 seconds. . .")
        time.sleep(190)
        print("Continue")
        if ping == 0:
            print(f"Your {get_cpuinfo_func()} successfully updated to openwrt-version-{version}!")
        #    return True
        else:
            print(f"Did not find updated device - debug / restart it")
        #    return False

    if device == "microuter":
        execute(ip, version, filename["microuter"], filename_difference["microuter"])
    elif device == "viwib":
        execute(ip, version, filename["viwib"], filename_difference["viwib"])
    elif device == "viwib2":
        execute(ip, version, filename["viwib2"], filename_difference["viwib2"])
    elif device == "vigir":
        execute(ip, version, filename["vigir"], filename_difference["vigir"])
    else:
        print("The device is not reachable")

# basic configuration
def configuration(device):
    print(f"starting configuration of your {device}")

    def config_microuter():
        return "Configure microuter"

    def config_viwib():
        print("Configure viwib")

    def config_viwib2():
        print("works !!Configure viwib2")

    def config_vigir():

     #   connect = f"ssh root@{ip}"
        subprocess.call([f'ssh-keygen -R {ip}'], shell=True)

        # Set IPv6 address on LAN
        vigir_id_short = vigir_id[1:]
        subprocess.call([f"ssh root@{ip} uci set network.lan.ip6addr='****:****:{vigir_id_short}:****::**/**'"], shell=True)

        # Do not announce ULA - we have GUA
        subprocess.call([f"ssh root@{ip} uci delete network.globals.ula_prefix"], shell=True)

        # Setup Router Advertisements / remove IPv4 dhcp
        subprocess.call([f"ssh root@{ip} uci set dhcp.lan.ra='server'"], shell=True)

        # We do stateless by default everywhere
        subprocess.call([f"ssh root@{ip} uci delete dhcp.lan.dhcpv6"], shell=True)

        # Fix DNS: make dnsmasq NOT use a resolv.conf
        # so that it only reads from our servers with DNS64 enabled
        subprocess.call([f"ssh root@{ip} uci set dhcp.@dnsmasq[0].noresolv='1'"], shell=True)

        # Fix DNS: make the OS use the locally provided DNS servers
        # otherwise the VPN tunnel cannot be established
        subprocess.call([f"ssh root@{ip} uci set dhcp.@dnsmasq[0].localuse='0'"], shell=True)

        # DNS upstream over VPN gives DNS64
        subprocess.call([f"ssh root@{ip} uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci add_list dhcp.@dnsmasq[0].server='****:****:*:*::*'"], shell=True)

        # Set Hostname
        subprocess.call([f"ssh root@{ip} uci set system.@system[0].hostname='vigir-{vigir_id}'"], shell=True)

        # Wifi configuration
        subprocess.call([f"ssh root@{ip} uci set wireless.radio0=wifi-device"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.radio0.htmode='HT40'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.radio0.channel='6'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.radio0.country='CH'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.default_radio0.encryption='psk2'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.default_radio0.key='******'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.default_radio0.ssid='*****-{vigir_id}'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.radio1.country='CH'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.default_radio1.encryption='psk2'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.default_radio1.key='*****'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set wireless.default_radio1.ssid='*****-{vigir_id}_5Ghz'"], shell=True)

        # Ensure it is not disabled
        subprocess.call([f"ssh root@{ip} uci delete wireless.radio0.disabled"], shell=True)
        subprocess.call([f"ssh root@{ip} uci delete wireless.radio1.disabled"], shell=True)
        # Create temporary IPV4 CLIENT on LAN
        # This way we get Internet/upstream from the LAN port
        # Can we do this via IPv6 instead?
        # this breaks if multiple vigir are setup, as we have fake / wrong
        # dhcp server configurations.
        # easy solution: using two different networks...
        # changed ipv4 from vigir 21 to 192.168.8.1

        subprocess.call([f"ssh root@{ip} uci commit"], shell=True)
        subprocess.call([f"ssh root@{ip} reboot"], shell=True)

        # wait for reboot
        print("waiting 60 seconds. . .")
        time.sleep(60)
        print("continue")

        # update the source
        subprocess.call([f"ssh root@{ip} opkg update"], shell=True)
        subprocess.call([f"ssh root@{ip} opkg install luci-app-wireguard luci-proto-wireguard"], shell=True)

        # VPN / Wireguard
        subprocess.call([f"ssh root@{ip} uci set network.wg0=interface"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set network.wg0.proto='wireguard'"], shell=True)

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
        print(f'your privatekey = {client_privatekey}\nyour publickey = {client_publickey}')

        #continue VPN / Wireguard
        subprocess.call([f"ssh root@{ip} uci set network.wg0.private_key='{client_privatekey}'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set network.wg0.listen_port='51820'"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set network.wg0.addresses='****:****:{vigir_id_short}::**/**'"], shell=True)

        # if ! uci get network.@wireguard_wg0[0]; then  uci add network wireguard_wg0 fi
        # get a non-zero exit error if "uci: Entry not found"

        # """""
        # stored_output_wg0 = b'wireguard_wg0'
        # output_wg0 = subprocess.check_output([f"ssh root@{ip} uci get network.@wireguard_wg0[0]"], shell=True)
        # if stored_output_wg0 in output_wg0:
        #     print("True")
        # else:
        #     print("False")
        # """

        # continue VPN / Wireguard
        subprocess.call([f"ssh root@{ip} uci add network wireguard_wg0"], shell=True)
        subprocess.call([f"ssh root@{ip} uci set network.@wireguard_wg0[0].persistent_keepalive='25'"], shell=True)
        vpn_endpoint_publickey = "******"
        subprocess.call([f'ssh root@{ip} uci set network.@wireguard_wg0[0].public_key="{vpn_endpoint_publickey}"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.@wireguard_wg0[0].description="****"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.@wireguard_wg0[0].allowed_ips="::/0"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.@wireguard_wg0[0].endpoint_host="vpn-***.**.ch"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.@wireguard_wg0[0].endpoint_port="51820"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.@wireguard_wg0[0].route_allowed_ips="1"'], shell=True)


        ### changed ipv4 from vigir 21 to 192.168.8.1
        # Configure VPN-Server
        print('connecting to wireguard server')
        rainbow_ip = '****:****:*:*:****:****:****:****'
        subprocess.call([f'ssh root@{rainbow_ip} wg set wg0 peer {client_publickey} allowed-ips ****:****:{vigir_id_short}::/48'], shell=True)
        print('wireguard settings complete')
        ###


        # Firewall configuration
        #if ! uci show firewall | grep "name='Allow-SSH'"; then
        subprocess.call([f'ssh root@{ip} uci add firewall rule'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].name="Allow-SSH"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].src="wan"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].dest="lan"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].proto="tcp"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].dest_port="22"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].target="ACCEPT"'], shell=True)
        #fi
        #####
        #if ! uci show firewall | grep "name='Allow-HTTPS'"; then
        subprocess.call([f'ssh root@{ip} uci add firewall rule'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].name="Allow-HTTPS"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].src="wan"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].dest="lan"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].proto="tcp"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].dest_port="443"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].target="ACCEPT"'], shell=True)
        #fi
        #####
        #if ! uci show firewall | grep "name='Allow-HTTP'"; then
        subprocess.call([f'ssh root@{ip} uci add firewall rule'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].name="Allow-HTTP"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].src="wan"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].dest="lan"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].proto="tcp"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].dest_port="80"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@rule[-1].target="ACCEPT"'], shell=True)
        #fi

        subprocess.call([f'ssh root@{ip} uci set firewall.@zone[1].network="wan"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@zone[1].network="wan6"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set firewall.@zone[1].network="wg0"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci commit'], shell=True)
        subprocess.call([f'ssh root@{ip} reboot'], shell=True)

        print("waiting 60 seconds. . .")
        time.sleep(60)
        print(f'your vigir has been successfully configured.')
        print('######')
        print('If the WG configuration has not yet been updated:')
        print(f'please enter the following command in the wireguard server(****:****:*:*:****:****:****:****): \n "wg set wg0 peer {client_publickey} allowed-ips ****:****:{vigir_id_short}::/48"')
        print('######')


    # Call the basic config function
    if device == "microuter":
        config_microuter()
    elif device == "viwib":
        config_viwib()
    elif device == "viwib2":
        config_viwib2()
    elif device == "vigir":
        config_vigir()
    else:
        print("The device is not reachable")

    #########
    # before this works the peer on the wg server must be set
    #########
    def qmi_conf_vigir():
        print('Configuration QMI-LTE-Modem')

        subprocess.call([f'ssh root@{ip} opkg update'], shell=True)
        subprocess.call([f'ssh root@{ip} opkg install libustream-openssl ca-bundle ca-certificates'], shell=True)
        subprocess.call([f'ssh root@{ip} opkg install kmod-usb-net-qmi-wwan uqmi luci-proto-qmi'], shell=True)

        # Create Interface
        subprocess.call([f'ssh root@{ip} uci set network.lte=interface'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.lte.device="/dev/cdc-wdm0"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.lte.proto="qmi"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.lte.apn="internet"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.lte.auth="both"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.lte.modes="lte"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.lte.pdptype="ipv4"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.lte.username="any"'], shell=True)
        subprocess.call([f'ssh root@{ip} uci set network.lte.password="any"'], shell=True)

        # add to correct firewall zone
        # doesnt work right, but the current network is wg0
        """
        current_networks = subprocess.check_output([f'uci get firewall.@zone[1].network'], shell=True)
        print(current_networks)
        """
        subprocess.call(["ssh", f"root@{ip}", "uci", "set", "firewall.@zone[1].network='wg0 lte'"])
        subprocess.call([f'ssh root@{ip} uci commit'], shell=True)
        subprocess.call([f'ssh root@{ip} reboot'], shell=True)
        print('your vigir has been successfully qmi-lti configured.')

    if qmi != False:
        qmi_conf_vigir()
    else:
        print(f'no qmi-lte config')
    #########


# pinging and check which device is plugged in
if ping == 0 and get_cpuinfo_func() == "microuter":
    firmware_update("microuter")
elif ping == 0 and get_cpuinfo_func() == "viwib":
    firmware_update("viwib")
elif ping == 0 and get_cpuinfo_func() == "viwib2":
    firmware_update("viwib2")
elif ping == 0 and get_cpuinfo_func() == "vigir":
    firmware_update("vigir")
else:
    print("The device is not reachable")

device = get_cpuinfo_func()
#if firmware_update(device) == True:
#    configuration(f"{get_cpuinfo_func()}")

configuration(f"{get_cpuinfo_func()}")
