#!/usr/bin/env python3
# Author: YOGI SI CYBER ANOMALI
# Cross-Platform Pentest Tool

import os
import sys
import time
import socket
import random
import threading
import requests
import platform
from bs4 import BeautifulSoup
from colorama import Fore, init
from tabulate import tabulate

# Termux compatibility
if 'termux' in os.environ.get('PREFIX', ''):
    from android import android as android_utils

init(autoreset=True)

# Global variables
attack_running = True
packet_count = 0
start_time = 0
TERMUX = 'termux' in os.environ.get('PREFIX', '')

# Banner
def banner():
    print(Fore.RED + """
    ██╗   ██╗ ██████╗  ██████╗ ██╗    ██████╗ ██████╗  █████╗ ██████╗ 
    ╚██╗ ██╔╝██╔═══██╗██╔═══██╗██║    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗
     ╚████╔╝ ██║   ██║██║   ██║██║    ██████╔╝██████╔╝███████║██████╔╝
      ╚██╔╝  ██║   ██║██║   ██║██║    ██╔══██╗██╔══██╗██╔══██║██╔══██╗
       ██║   ╚██████╔╝╚██████╔╝██║    ██║  ██║██████╔╝██║  ██║██║  ██║
       ╚═╝    ╚═════╝  ╚═════╝ ╚═╝    ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    """ + Fore.CYAN + "CROSS-PLATFORM PENTEST TOOL - YOGI SI CYBER ANOMALI\n" + Fore.RESET)

def install_dependencies():
    """Install required dependencies for both Termux and Linux"""
    packages = [
        'python', 'clang', 'openssl', 'libffi', 'python-pip',
        'nmap', 'curl', 'git', 'wget', 'libxml2', 'libxslt'
    ]
    
    print(Fore.YELLOW + "[+] Menginstall dependensi..." + Fore.RESET)
    
    if TERMUX:
        os.system('pkg update -y && pkg upgrade -y')
        os.system('pkg install -y ' + ' '.join(packages))
    else:
        os.system('sudo apt update && sudo apt install -y python3 python3-pip nmap curl git')
    
    pip_packages = [
        'requests', 'bs4', 'colorama', 'tabulate', 'scapy',
        'geoip2', 'phonenumbers', 'python-whois'
    ]
    os.system(f'pip3 install --user {" ".join(pip_packages)}')

# ... [Fungsi lainnya tetap sama, modifikasi bagian berikut] ...

# Enhanced IP Geolocation (Termux compatible)
def ip_geolocation():
    ip = input(Fore.YELLOW + "[?] Masukkan IP: " + Fore.RESET)
    
    try:
        geo_path = '/data/data/com.termux/files/usr/share/GeoIP/GeoLite2-City.mmdb'
        if not os.path.exists(geo_path):
            print(Fore.YELLOW + "[!] Mengunduh database GeoIP..." + Fore.RESET)
            os.system('mkdir -p $PREFIX/share/GeoIP')
            os.system('wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz')
            os.system('tar -xf GeoLite2-City.tar.gz -C $PREFIX/share/GeoIP/')
        
        reader = geoip2.database.Reader(geo_path)
        response = reader.city(ip)
        
        data = [
            ["IP Address", ip],
            ["Country", f"{response.country.name} ({response.country.iso_code})"],
            ["City", response.city.name],
            ["Location", f"{response.location.latitude}, {response.location.longitude}"],
            ["ISP", requests.get(f"https://ipinfo.io/{ip}/json").json().get('org', 'Unknown')]
        ]
        
        print("\n" + tabulate(data, tablefmt="grid"))
        print(Fore.CYAN + f"\nGoogle Maps: https://maps.google.com/?q={response.location.latitude},{response.location.longitude}")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}" + Fore.RESET)
        os.system(f"curl ipinfo.io/{ip}")

# WhatsApp Spammer (Termux compatible)
def whatsapp_spam():
    phone = input(Fore.YELLOW + "[?] Nomor WhatsApp (contoh: 628123456789): " + Fore.RESET)
    msg = input("[?] Pesan: ")
    count = int(input("[?] Jumlah spam: ") or 50)
    delay = float(input("[?] Delay antar pesan (detik): ") or 1)
    
    print(Fore.RED + f"\n[!] Mengirim {count} pesan ke {phone}" + Fore.RESET)
    
    url = f"https://web.whatsapp.com/send?phone={phone}&text={msg}"
    
    for i in range(count):
        try:
            if TERMUX:
                os.system(f'am start -a android.intent.action.VIEW -d "{url}"')
            else:
                os.system(f"xdg-open '{url}' >/dev/null 2>&1")
            print(f"[{i+1}/{count}] Pesan terkirim")
            time.sleep(delay)
        except:
            print(Fore.RED + f"[{i+1}/{count}] Gagal mengirim" + Fore.RESET)

if __name__ == "__main__":
    try:
        # Check dependencies first
        if not os.path.exists('/data/data/com.termux/files/usr/bin/python') and not os.path.exists('/usr/bin/python3'):
            install_dependencies()
            
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Tool dihentikan" + Fore.RESET)
        sys.exit(0)