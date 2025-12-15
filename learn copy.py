import subprocess
import os
from datetime import datetime

newpath = r'Reports' 
if not os.path.exists(newpath):
    os.makedirs(newpath)

timestamp = datetime.now().strftime("%d_%m_%Y_%H%M")

def nmap():

    target = input("Enter target (like 192.168.1.1): ")

    # Show options
    print("\nChoose scan type:")
    print("1. Quick scan -T4 -F")
    print("2. Stealth scan sS") 
    print("3. Full scan -sV -sC -A -O ")
    print("4. Find services -sV")
    print("5. Find OS -O")

    # Get choice
    choice = input("\nEnter number (1-5): ")

    # Make command string
    if choice == "1":
        cmd = f"nmap -T4 -F {target}"  # Quick
    elif choice == "2":
        cmd = f"nmap -sS {target}"  # Stealth
    elif choice == "3":
        cmd = f"nmap -sV -sC -A -O {target}"  # Full
    elif choice == "4":
        cmd = f"nmap -sV {target}"  # Services
    elif choice == "5":
        cmd = f"nmap -O {target}"  # OS
    else:
        print("Wrong choice!")
        exit()

    # Show what we're doing
    print(f"\nRunning: {cmd}")
    print("-" * 30)


    with open(f"Reports/nmap_scan_{target}-{timestamp}.txt", "w") as f:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout)

def manu():
    print("1: Select Nmap")
    choice = int(input("Select A Tool To Use: "))

    if choice == 1:
        nmap()
manu()