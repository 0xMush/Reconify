import subprocess
import os
from datetime import datetime
import requests
from colorama import init, Fore, Back, Style

newpath = r'Reports' 
if not os.path.exists(newpath):
    os.makedirs(newpath)

timestamp = datetime.now().strftime("%d_%m_%Y_%H%M")

def nmap():

    target = input("Enter target (like 192.168.1.1): ")

    print("\nChoose scan type:")
    print("1. Quick scan -T4 -F")
    print("2. Stealth scan sS") 
    print("3. Full scan -sV -sC -A -O ")
    print("4. Find services -sV")
    print("5. Find OS -O")

    choice = input("\nEnter number (1-5): ")

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

    print(f"\nRunning: {cmd}")
    print("-" * 30)


    with open(f"Reports/nmap_scan_{target}-{timestamp}.txt", "w") as f:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        f.write(result.stdout)
        print(result.stdout)




def ai_chat():
    print("Get Your sk key from openrouter website and paste that in key.txt file")
    # Get API key
    with open("key.txt", "r") as f:
        api_key = f.read().strip()

    # Get file to analyze
    file_name = input("Enter your Nmap file name: ")

    # Read the file
    with open(file_name, "r") as f:
        nmap_data = f.read()

    def main_menu():
        print("1: Analyze Old Components/Services With Cve's")
        print("2: Analyze Running Services And Attacks")
        print("3: Analyze whats wrong with your scan")
        print("4: Custom Prompt")
        choice = int(input("Input Your Choice: "))
        
        if choice == 1:
            return "Analyze this Scan for Old Components/Services With Cve's if a component is old with a Small warning"
        elif choice == 2:
            return "Analyze Running Services And Possible Attacks"
        elif choice == 3:
            return "Analyze this Nmap scan and tell me what's wrong with it"
        elif choice == 4:
            return input("Enter your custom prompt: ")
        else:
            return "Analyze this Nmap scan"

    # Get the prompt from the menu
    aiprompt = main_menu()
    
    # Send to AI
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        },
        json={
            "model": "tngtech/deepseek-r1t2-chimera:free",
            "messages": [
                {
                    "role": "user", 
                    "content": f"{aiprompt}:\n\n{nmap_data}"
                }
            ]
        }
    )

    # Show the result
    result = response.json()
    print("\nAI Analysis:\n")
    print(result['choices'][0]['message']['content'])

    # Run the function
    ai_chat()


def ffuf_scanner():
        print("FFUF Directory/Subdomain Scanner")
        print("=" * 40)
        
        target = input("Enter target URL (like https://example.com or http://192.168.1.1): ")
        
        wordlist = input("Enter wordlist file path: ")
        
        
        print("\nChoose scan type:")
        print("1. Quick directory scan")
        print("2. file/Directory scan with extensions")
        print("3. Subdomain discovery")
        print("4. File fuzzing with extensions")
        
        choice = input("\nEnter number (1-4): ")
        
        if choice == "1":
            cmd = f"ffuf -u {target}/FUZZ -w {wordlist} -mc 200,301,302,403"
            output_file = f"Reports/ffuf_dir_{timestamp}.txt"
        elif choice == "2":
            cmd = f"ffuf -u {target}/FUZZ -w {wordlist} -e .php,.html,.txt -mc 200,301,302,403"
            output_file = f"Reports/ffuf_dir_ext_{timestamp}.txt"
        elif choice == "3":
            cmd = f"ffuf -u {target} -H 'Host: FUZZ.example.com' -w {wordlist} -mc 200,301,302"
            output_file = f"Reports/ffuf_subdomains_{timestamp}.txt"
        elif choice == "4":
            cmd = f"ffuf -u {target}FUZZ -w {wordlist} -e .php,.bak,.txt -mc 200,301,302,403"
            output_file = f"Reports/ffuf_files_{timestamp}.txt"
        else:
            print("Wrong choice!")
            exit()
        
        print(f"\nRunning: {cmd}")
        print("-" * 30)
        
        with open(output_file, "w") as f:
            result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
            f.write(result.stdout)
            print(result.stdout)
 

def wpscan_tool():
    print("WPScan WordPress Scanner")
    print(Fore.RED + "Add wpscan api in wpscankey.txt Before using it" + Style.RESET_ALL)
    print("=" * 40)
    
    target = input("Enter WordPress site URL: ")
    
    # Read API key
    with open("wpscankey.txt", "r") as f:
        api_key = f.read().strip()
    
    
    print("\nChoose scan type:")
    print("1. Basic scan")
    print("2. Full scan")
    print("3. Plugin scan")
    
    choice = input("\nEnter number (1-3): ")
    
    base_cmd = f"wpscan --url {target} --api-token {api_key}"
    
    if choice == "1":
        cmd = f"{base_cmd} --enumerate"
        output_file = f"Reports/wpscan_basic_{timestamp}.txt"
    elif choice == "2":
        cmd = f"{base_cmd} --enumerate vp,vt,u"
        output_file = f"Reports/wpscan_full_{timestamp}.txt"
    elif choice == "3":
        cmd = f"{base_cmd} --enumerate vp"
        output_file = f"Reports/wpscan_plugins_{timestamp}.txt"
    else:
        print("Wrong choice!")
        exit()
    
    print(f"\nRunning: {cmd}")
    print("-" * 30)
    
    with open(output_file, "w") as f:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        f.write(result.stdout)
        print(result.stdout)

    wpscan_tool()

def manu():
    print(Back.GREEN + "1: Nmap"+ Style.RESET_ALL)
    print(Back.GREEN + "2: Nmap Scan Ai Analyzer" + Style.RESET_ALL )
    print(Back.GREEN + "3: FFUF (directry/subdomain/files Bruteforce Tool)" + Style.RESET_ALL)
    print(Back.GREEN + "4: WPscan (usage with api)" + Style.RESET_ALL)
    choice = int(input("Select A Tool To Use: "))

    if choice == 1:
        nmap()
    elif choice == 2:
        ai_chat()
    elif choice == 3:
        ffuf_scanner()  
    elif choice == 4:
        wpscan_tool()

manu()