from Network.Devices import Spokes, Area_0, Area_10, Area_23, Firewall_A_10, Firewalls_A_51
from itertools import chain
from netmiko import ConnectHandler
from rich import print as rp


#Configure DHCP helper address
for devices in Spokes.values():
    c = ConnectHandler(**devices)
    c.enable()
    commands = ['int e0/0', 'ip helper-address 192.168.10.254']
    rp(c.send_config_set(commands))
    c.save_config()
    c.disconnect()
    print('\n)')


# #Configuring SNMP on all devices
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),Area_10.values(),Area_23.values()):
    c = ConnectHandler(**devices)
    c.enable()
    commands = ['ip access-list standard SNMP-ACL',
                'permit host 192.168.10.254',
                'snmp-server system-shutdown',
                'snmp-server community device_snmp SNMP-ACL',
                'snmp-server enable traps config',
                'snmp-server host 192.168.10.254 traps version 2c device_snmp']
    rp(c.send_config_set(commands),'\n')
    c.save_config()
    c.disconnect()


#Configuring NetFlow on Spoke routers and Area 23 routers
for devices in chain(Spokes.values(), Area_23.values()):
    c = ConnectHandler(**devices)
    c.enable()
    host = c.send_command('show version',use_textfsm=True)[0]['hostname']
    interface = input(f'{host}{" "}Source Interface: ')
    udp_port  = input(f'{host}{" "}UDP port: ')
    commands  = ['ip flow-export version 9',
                 'ip flow-export source '+interface,
                 'ip flow-export destination 192.168.10.254 '+udp_port,
                 'ip flow-cache timeout active 1',
                 'interface '+interface,
                 'ip nbar protocol-discovery',
                 'ip flow ingress',
                 'ip flow egress',
                 ]
    rp(c.send_config_set(commands),'\n')
    c.save_config()
    c.disconnect()
    

# #Configuring Access-class restricting remote connection to 192.168.2.0/24
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),Area_10.values(),Area_23.values()):
    c = ConnectHandler(**devices)
    c.enable()

    commands = ['ip access-list extended VTY_ACL',
                'permit tcp 192.168.2.0 0.0.0.255 any eq 22',
                'permit tcp host 192.168.11.100 any eq 22',
                'deny tcp any any log',
                'line vty 0 4',
                'logging sync',
                'no privilege level 15',
                'access-class VTY_ACL in']
    rp(c.send_config_set(commands),'\n')
    c.save_config()
    c.disconnect()


#Getting Running configurations:
filepath = input('Input backup filepath: ')
for devices in chain(Spokes.values(),Firewall_A_10.values(),Area_0.values(),Area_10.values(),Area_23.values(),Firewalls_A_51.values()):
    c = ConnectHandler(**devices)
    c.enable()
    host = c.send_command('show version',use_textfsm=True)[0]['hostname']
    output = c.send_command('show run')
    with open (f'{filepath}/{host}','w') as f:
        f.write(output)
        c.disconnect()
    rp(f'The running-configuration of ',host,' has been successfully backed up!!')


#Configuring Crytography on DMVPN network:
secret_key = input('Input pre-shared key: ')
for devices in chain(Firewalls_A_51.values(),Spokes.values()):
    c = ConnectHandler(**devices)
    c.enable() 
    commands = ['crypto isakmp policy 100',
                'hash sha256',
                'authentication pre-share',
                'group 14',
                'lifetime 7200',
                'encryption aes 192',
                'crypto isakmp key '+secret_key+' address 0.0.0.0',
                'crypto ipsec transform-set Crypt-ts esp-sha256-hmac esp-aes 192',
                'mode transport',
                'crypto ipsec profile Crypt_profile',
                'set transform-set Crypt-ts']
    rp(c.send_config_set(commands),'\n')
    c.save_config()
    c.disconnect()

#Configuring NTP on HUB and Spoke routers
for devices in chain(Firewalls_A_51.values()):
    c = ConnectHandler(**devices)
    c.enable()
    commands = ['ip domain lookup',
                'ip name-server 8.8.8.8 192.168.10.254',
                'ntp server ke.pool.ntp.org',
                'clock timezone UTC +3',
                'service timestamps log datetime localtime year',
                'service timestamps debug datetime localtime year']
    rp(c.send_config_set(commands),'\n')
    c.save_config()
    c.disconnect()


#Configuring MOTD login banner
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),Area_10.values(),Area_23.values()):
    c = ConnectHandler(**devices)
    c.enable()
    host = c.send_command('show version',use_textfsm=True)[0]['hostname']
    commands = [
                'banner login @',
               f'{"*"*50}\n',
               f'{" "*10}{host}-ROUTER\n',
               f'{" "*5}Configured using CLI and Netmiko\n',
               f'{" "}Unauthorized access is strictly forbidden\n',
               f'{"*"*50}\n',
               '@']
    rp(c.send_config_set(commands),'\n')
    c.save_config()
    c.disconnect()



#Configuring MOTD login banner
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),Area_10.values(),Area_23.values()):
    c = ConnectHandler(**devices)
    c.enable()
    commands = ['ip access-list standard Nat_acl',
                'permit 192.168.10.0 0.0.1.255',
                'permit 192.168.2.0 0.0.1.255',
                'ip nat inside source list Nat_acl int e0/3 overload',
                'int range e0/0-1',
                'ip nat inside',
                'int e0/3',
                'ip nat outside',
               ]
    rp(c.send_config_set(commands),'\n')
    c.save_config()
    c.disconnect()


#Verifying OSPF routes:
filepath = input('Input OSPF backup filepath: ')
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),Area_10.values(),Area_23.values()):
    c = ConnectHandler(**devices)
    c.enable()
    host = c.send_command('show version',use_textfsm=True)[0]['hostname']
    output = c.send_command('show ip route ospf',use_textfsm=True)
    with open (f'{filepath}/{host}{" "}Routes','w') as f:
        f.write(output)
        c.disconnect()
    rp(f'{host}{" "}Routes have been documented!!')
print('\n')



#Verifying EIGRP routes:
filepath = input(f'Input EIGRP backup filepath: ')
for devices in chain(Firewalls_A_51.values(),Spokes.values()):
    c = ConnectHandler(**devices)
    c.enable()
    host = c.send_command('show version',use_textfsm=True)[0]['hostname']
    output = c.send_command('show ip route eigrp',use_textfsm=True)
    with open (f'{filepath}/{host}{" "}Routes','w') as f:
        f.write(output)
        c.disconnect()
    rp(f'{host}{" "}Routes have been documented!!')