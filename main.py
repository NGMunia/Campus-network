from Network.Devices import Spokes, Area_0, Area_10, Area_23, Firewall_A_10, Firewalls_A_51
from itertools import chain
from netmiko import ConnectHandler
from rich import print as rp
from csv import writer


#Configure DHCP helper address
for devices in Spokes.values():
    c = ConnectHandler(**devices)
    c.enable()
    commands = ['int e0/0', 'ip helper-address 192.168.10.254']
    rp(c.send_config_set(commands))
    c.save_config()
    c.disconnect()
    print('\n')


#Configuring SNMP on all devices
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),
                     Area_10.values(),Area_23.values(), Spokes.values()):
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
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),Area_10.values(),
                     Area_23.values(), Spokes.values()):
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
for devices in chain(Spokes.values(),Firewall_A_10.values(),Area_0.values(),Area_10.values(),Area_23.values(),
                     Firewalls_A_51.values()):
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
for devices in chain(Firewall_A_10.values(),Firewalls_A_51.values(), Area_0.values(),Area_10.values(),
                     Area_23.values(),Spokes.values()):
    c = ConnectHandler(**devices)
    c.enable()
    host = c.send_command('show version',use_textfsm=True)[0]['hostname']
    commands = [
                'banner login @',
               f'{"*"*50}',
               f'{" "*10}{host}-ROUTER',
               f'{" "*5}Configured using CLI and Netmiko',
               f'{" "}Unauthorized access is strictly forbidden',
               f'{"*"*50}',
               '@']
    rp(c.send_config_set(commands),'\n')
    c.save_config()
    c.disconnect()


#Configuring NAT
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),
                     Area_10.values(),Area_23.values()):
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
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),
                     Area_10.values(),Area_23.values()):
    c = ConnectHandler(**devices)
    c.enable()
    host = c.send_command('show version',use_textfsm=True)[0]['hostname']
    output = c.send_command('show ip route ospf',use_textfsm=True)
    with open (f'{filepath}/{host}{" "}Routes','w') as f:
        f.write(output)
        c.disconnect()
    rp(f'{host}{" "}Routes have been documented!!')



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


#Configuring Syslog:
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),
                     Area_10.values(),Area_23.values(),Spokes.values()):
    c = ConnectHandler(**devices)
    c.enable()
    commands = ['logging monitor informational',
                'logging host 192.168.10.254']
    rp(c.send_config_set(commands),'\n')
    c.save_config()
    c.disconnect()
    
    

#Running configuration backup
Backup_path = input('Backup path: ')
for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),
                     Area_10.values(),Area_23.values(),Spokes.values()):
    c = ConnectHandler(**devices)
    c.enable()
    host =  c.send_command('show version',use_textfsm=True)[0]['hostname']
    output = c.send_command('show running-config')
    with open (f'{Backup_path}/{host}','w') as f:
        f.write(output)
        c.disconnect()
    rp(f'{host}{" "}Running configuration backed up successfully!!')



#Inventory
filepath = input('Inventory filepath: ')
with open (f'{filepath}/Data.csv', 'w')as f:
    write_data = writer(f)
    write_data.writerow(['Hostname','IP address','Software Image','Version','Serial number','Hardware'])
    for devices in chain(Firewall_A_10.values(), Firewalls_A_51.values(), Area_0.values(),
                         Area_10.values(),Area_23.values(),Spokes.values()):
        c = ConnectHandler(**devices)
        c.enable()
        output = c.send_command('show version',use_textfsm=True)[0]

        hostname = output['hostname']
        ip_addr  = devices['ip']
        image    = output['software_image']
        version  = output['version']
        serial   = output['serial']
        hardware = output['hardware']

        write_data.writerow([hostname,ip_addr,image,version,serial,hardware])
        rp(f'Finished taking {hostname} Inventory')
        c.disconnect()

        
    
   

