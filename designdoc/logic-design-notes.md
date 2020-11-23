- Overview:
-- The solution comprises 2 executable: 
--- A GUI application for user to interact with
--- A console application acts at the solution entry point and also a bridge to execute shell scripts to update firewall rules
-- The user typically call the console app with no arguments to fire up the GUI.
-- The GUI will call the console app with specific arguments to execute shell command (the arguments will be simplified.
E.g: bridge.exe iptables rules --> bridge will return all rules as text and GUI app will read it.
bridge.exe iptables '-A OUTPUT -p tcp --dport http -j DROP' -> bridge will try to execute this rule.
E.g.2:
```
xceeded@xceeded:~/CodeBlocks/Bridge/bin/Debug$ ./Bridge iptables -A OUTPUT -p tcp --dport http -j DROP
Passed in 10parameters:
./Bridge
iptables
-A
OUTPUT
-p
tcp
--dport
http
-j
DROP
xceeded@xceeded:~/CodeBlocks/Bridge/bin/Debug$ ./Bridge iptables '-A OUTPUT -p tcp --dport http -j DROP'
Passed in 3parameters:
./Bridge
iptables
-A OUTPUT -p tcp --dport http -j DROP
xceeded@xceeded:~/CodeBlocks/Bridge/bin/Debug$ 
```
*=> GUI app will pass in a string for long commands*

==
Parsing IP Tables -save

-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-N f2b-icmp-ping
-A INPUT -p icmp -j f2b-icmp-ping
-A f2b-icmp-ping -s 127.0.1.1/32 -j DROP
-A f2b-icmp-ping -s 10.0.134.198/32 -j DROP

**
-P: Policy flag: specify table default policy
-N: create new table
-A: append rule to table
