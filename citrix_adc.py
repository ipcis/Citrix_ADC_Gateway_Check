# CoreThreat - Citrix ADC & Gateway version check
# written by https://twitter.com/marcelbilal
# https://blog.fox-it.com/2022/12/28/cve-2022-27510-cve-2022-27518-measuring-citrix-adc-gateway-version-adoption-on-the-internet/

import requests, re, csv, sys

requests.packages.urllib3.disable_warnings() 

def banner():
    print()
    print("###################################################")
    print("# CoreThreat - Citrix ADC & Gateway version check #")
    print("#  written by https://twitter.com/marcelbilal     #")
    print("#  Credits to Fox-IT                              #")
    print("###################################################")
    print()


def main():
    banner()
    try:
        target = sys.argv[1]
        hash_list = get_hash_table()

        if(target == "-h"):
            print("Usage: <script> <ip>")
            print("or <script> -list")
            return 0

        if(target == "-list"):
            with open('ips.txt') as f:
                lines = f.readlines()
                for line in lines:
                    target = line.replace(' ', '').replace('\r','').replace('\n','')
                    connect_to_target(hash_list, target)
        else:
            connect_to_target(hash_list, target)
    except:
        print("[!] Please set target ip")
        return 0



def get_hash_table():
    CSV_URL = 'https://gist.githubusercontent.com/fox-srt/c7eb3cbc6b4bf9bb5a874fa208277e86/raw/20c413676b8ad8b3327040b2b3120fadc128acc1/citrix-adc-version-hashes.csv'


    with requests.Session() as s:
        download = s.get(CSV_URL)

        decoded_content = download.content.decode('utf-8')

        cr = csv.reader(decoded_content.splitlines(), delimiter=',')
        my_list = list(cr)

        return my_list
        


def connect_to_target(my_list, target):
    print("[+] Connect to target: ", target)

    try:
        r = requests.get("https://" + target + "/vpn/index.html", verify=False)
    except:
        print("[!] Failed connecting to target")
        return 0

    #print('Body')
    #print (r.text)

    if r.status_code == 200:
        r1 = re.findall(r'v=(.*?)"><',r.text)

        detect_version = False

        if len(r1) > 0:
            vhash = r1[0]
            print("[+] Found hash:", vhash)

            for row in my_list:
                if vhash in row:    
                    print("[+] Found version: ", row)
                    detect_version = True

            if detect_version == False:
                print("[+] Could not detect version: ", vhash)


if __name__ == "__main__":
    main()
