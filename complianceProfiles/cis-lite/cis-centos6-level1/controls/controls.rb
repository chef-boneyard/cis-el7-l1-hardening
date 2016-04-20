control "xccdf_org.cisecurity.benchmarks_rule_1.1.17_Set_Sticky_Bit_on_All_World-Writable_Directories" do
  title "Set Sticky Bit on All World-Writable Directories"
  desc  "Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them."
  impact 1.0
  describe command("find / -perm -00002 \\! -perm -01000") do
    its(:stdout) { should be_empty  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.1_Verify_CentOS_GPG_Key_is_Installed" do
  title "Verify CentOS GPG Key is Installed"
  desc  "CentOS cryptographically signs updates with a GPG key to verify that they are valid."
  impact 1.0
  describe package("gpg-pubkey") do
    it { should be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.2_Verify_that_gpgcheck_is_Globally_Activated" do
  title "Verify that gpgcheck is Globally Activated"
  desc  "The gpgcheck option, found in the main section of the /etc/yum.conf file determines if an RPM package's signature is always checked prior to its installation."
  impact 1.0
  describe file("/etc/yum.conf") do
    its(:content) { should match /^\s*gpgcheck=1\s*(#.*)?$/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.3_Obtain_Software_Package_Updates_with_yum" do
  title "Obtain Software Package Updates with yum"
  desc  "The yum update utility performs software updates, including dependency analysis, based on repository metadata and can be run manually from the command line, invoked from one of the provided front-end tools, or configured to run automatically at specified intervals."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.4_Verify_Package_Integrity_Using_RPM" do
  title "Verify Package Integrity Using RPM"
  desc  "RPM has the capability of verifying installed packages by comparing the installed files against the file information stored in the package."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.1_Set_UserGroup_Owner_on_etcgrub.conf" do
  title "Set User/Group Owner on /etc/grub.conf"
  desc  "Set the owner and group of /etc/grub.conf to the root user."
  impact 1.0
  describe file("/etc/grub.conf") do
    it { should exist  }
  end
  describe file("/etc/grub.conf") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/grub.conf") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.2_Set_Permissions_on_etcgrub.conf" do
  title "Set Permissions on /etc/grub.conf"
  desc  "Set permission on the /etc/grub.conf file to read and write for root only."
  impact 1.0
  describe file("/etc/grub.conf") do
    it { should exist  }
  end
  describe file("/etc/grub.conf") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/grub.conf") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/grub.conf") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/grub.conf") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/grub.conf") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/grub.conf") do
    it { should be_writable.by "other" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.3_Set_Boot_Loader_Password" do
  title "Set Boot Loader Password"
  desc  "Setting the boot loader password will require that the person who is rebooting the must enter a password before being able to set command line boot parameters"
  impact 1.0
  describe file("/etc/grub.conf") do
    its(:content) { should match /^password/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.4_Require_Authentication_for_Single-User_Mode" do
  title "Require Authentication for Single-User Mode"
  desc  "Since /etc/init determines what run state the system is in, setting the entry in /etc/sysconfig/init will force single user authentication."
  impact 1.0
  describe file("/etc/sysconfig/init") do
    its(:content) { should match /^\s*SINGLE=\/sbin\/sulogin/ }
  end
  describe file("/etc/sysconfig/init") do
    its(:content) { should match /^\s*PROMPT=no/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.5_Disable_Interactive_Boot" do
  title "Disable Interactive Boot"
  desc  "The PROMPT option provides console users the ability to interactively boot the system and select which services to start on boot ."
  impact 1.0
  describe file("/etc/sysconfig/init") do
    its(:content) { should match /^\s*PROMPT=no/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.1_Restrict_Core_Dumps" do
  title "Restrict Core Dumps"
  desc  "A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user."
  impact 1.0
  describe file("/etc/security/limits.conf") do
    its(:content) { should match /^\s*\*\shard\score\s0(\s+#.*)?$/ }
  end
  describe kernel_parameter("fs.suid_dumpable") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("fs.suid_dumpable") do
    its(:value) { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.2_Configure_ExecShield" do
  title "Configure ExecShield"
  desc  "Execshield is made up of a number of kernel features to provide protection against buffer overflow attacks. These features include prevention of execution in memory data space, and special handling of text buffers."
  impact 1.0
  describe kernel_parameter("kernel.exec-shield") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("kernel.exec-shield") do
    its(:value) { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.3_Enable_Randomized_Virtual_Memory_Region_Placement" do
  title "Enable Randomized Virtual Memory Region Placement"
  desc  "Set the system flag to force randomized virtual memory region placement."
  impact 1.0
  describe kernel_parameter("kernel.randomize_va_space") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("kernel.randomize_va_space") do
    its(:value) { should eq 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.1_Remove_telnet-server" do
  title "Remove telnet-server"
  desc  "The telnet-server package contains the telnetd daemon, which accepts connections from users from other systems via the telnet protocol."
  impact 1.0
  describe package("telnet-server") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.2_Remove_telnet_Clients" do
  title "Remove telnet Clients"
  desc  "The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol."
  impact 1.0
  describe package("telnet") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.3_Remove_rsh-server" do
  title "Remove rsh-server"
  desc  "The Berkeley rsh-server (rsh, rlogin, rcp) package contains legacy services that exchange credentials in clear-text."
  impact 1.0
  describe package("rsh-server") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.4_Remove_rsh" do
  title "Remove rsh"
  desc  "The rsh package contains the client commands for the rsh services."
  impact 1.0
  describe package("rsh") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.5_Remove_NIS_Client" do
  title "Remove NIS Client"
  desc  "The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client (ypbind) was used to bind a machine to an NIS server and receive the distributed configuration files."
  impact 1.0
  describe package("ypbind") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.6_Remove_NIS_Server" do
  title "Remove NIS Server"
  desc  "The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files."
  impact 1.0
  describe package("ypserv") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.7_Remove_tftp" do
  title "Remove tftp"
  desc  "Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot files between machines. TFTP does not support authentication and can be easily hacked. The package tftp is a client program that allows for connections to a tftp server."
  impact 1.0
  describe package("tftp") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.8_Remove_tftp-server" do
  title "Remove tftp-server"
  desc  "Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot machines from a boot server. The package tftp-server is the server package used to define and support a TFTP server."
  impact 1.0
  describe package("tftp-server") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.9_Remove_talk" do
  title "Remove talk"
  desc  "The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client (allows initialization of talk sessions) is installed by default."
  impact 1.0
  describe package("talk") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.10_Remove_talk-server" do
  title "Remove talk-server"
  desc  "The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client (allows initiate of talk sessions) is installed by default."
  impact 1.0
  describe package("talk-server") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.12_Disable_chargen-dgram" do
  title "Disable chargen-dgram"
  desc  "chargen-dram is a network service that responds with 0 to 512 ASCII characters for each datagram it receives. This service is intended for debugging and testing puposes. It is recommended that this service be disabled."
  impact 1.0
  describe.one do
    describe xinetd_conf.services("chargen").socket_types("dgram") do
    it { should be disabled  }
  end
  describe package("xinetd") do
    it { should_not be_installed  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.13_Disable_chargen-stream" do
  title "Disable chargen-stream"
  desc  "chargen-stream is a network service that responds with 0 to 512 ASCII characters for each connection it receives. This service is intended for debugging and testing puposes. It is recommended that this service be disabled."
  impact 1.0
  describe.one do
    describe xinetd_conf.services("chargen").socket_types("stream") do
    it { should be disabled  }
  end
  describe package("xinetd") do
    it { should_not be_installed  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.14_Disable_daytime-dgram" do
  title "Disable daytime-dgram"
  desc  "daytime-dgram is a network service that responds with the server's current date and time. This service is intended for debugging and testing purposes. It is recommended that this service be disabled."
  impact 1.0
  describe.one do
    describe xinetd_conf.services("daytime").socket_types("dgram") do
    it { should be disabled  }
  end
  describe package("xinetd") do
    it { should_not be_installed  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.15_Disable_daytime-stream" do
  title "Disable daytime-stream"
  desc  "daytime-stream is a network service that respondes with the server's current date and time. This service is intended for debugging and testing puposes. It is recommended that this service be disabled."
  impact 1.0
  describe.one do
    describe xinetd_conf.services("daytime").socket_types("stream") do
    it { should be disabled  }
  end
  describe package("xinetd") do
    it { should_not be_installed  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.16_Disable_echo-dgram" do
  title "Disable echo-dgram"
  desc  "echo-dgram is a network service that respondes to clients with the data sent to it by the client. This service is intended for debugging and testing puposes. It is recommended that this service be disabled."
  impact 1.0
  describe.one do
    describe xinetd_conf.services("echo").socket_types("dgram") do
    it { should be disabled  }
  end
  describe package("xinetd") do
    it { should_not be_installed  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.17_Disable_echo-stream" do
  title "Disable echo-stream"
  desc  "echo-stream is a network service that respondes to clients with the data sent to it by the client. This service is intended for debugging and testing puposes. It is recommended that this service be disabled."
  impact 1.0
  describe.one do
    describe xinetd_conf.services("echo").socket_types("stream") do
    it { should be disabled  }
  end
  describe package("xinetd") do
    it { should_not be_installed  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.18_Disable_tcpmux-server" do
  title "Disable tcpmux-server"
  desc  "tcpmux-server is a network service that allows a client to access other network services running on the server. It is recommended that this service be disabled."
  impact 1.0
  describe.one do
    describe xinetd_conf.services("tcpmux").socket_types("stream") do
    it { should be disabled  }
  end
  describe package("xinetd") do
    it { should_not be_installed  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.1_Set_Daemon_umask" do
  title "Set Daemon umask"
  desc  "Set the default umask for all processes started at boot time. The settings in umask selectively turn off default permission when a file is created by a daemon process."
  impact 1.0
  describe file("/etc/sysconfig/init") do
    its(:content) { should match /^\s*umask\s+027\s*(?:#.*)?$/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2_Remove_X_Windows" do
  title "Remove X Windows"
  desc  "The X Windows system provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on desktops where users login, but not on servers where users typically do not login."
  impact 1.0
  describe file("/etc/inittab") do
    its(:content) { should match /^\s*id:3:initdefault/ }
  end
  describe package("xorg-x11-server-common") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.3_Disable_Avahi_Server" do
  title "Disable Avahi Server"
  desc  "Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine."
  impact 1.0
  describe service("avahi-daemon").runlevels(/.*/) do
    it { should be_disabled  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4_Disable_Print_Server_-_CUPS" do
  title "Disable Print Server - CUPS"
  desc  "The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability."
  impact 0.0
  describe service("cups").runlevels(/.*/) do
    it { should be_disabled  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.5_Remove_DHCP_Server" do
  title "Remove DHCP Server"
  desc  "The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses."
  impact 1.0
  describe package("dhcp") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.6_Configure_Network_Time_Protocol_NTP" do
  title "Configure Network Time Protocol (NTP)"
  desc  "The Network Time Protocol (NTP) is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. The version of NTP delivered with CentOS can be found at http://www.ntp.org. NTP can be configured to be a client and/or a server."
  impact 1.0
  describe file("/etc/ntp.conf") do
    its(:content) { should match /^\s*restrict\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/ }
  end
  describe file("/etc/ntp.conf") do
    its(:content) { should match /^\s*restrict\s+-6\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/ }
  end
  describe file("/etc/ntp.conf") do
    its(:content) { should match /^\s*server\s+\S+/ }
  end
  describe file("/etc/sysconfig/ntpd") do
    its(:content) { should match /^\s*OPTIONS="[^"]*-u ntp:ntp[^"]*"\s*(?:#.*)?$/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.7_Remove_LDAP" do
  title "Remove LDAP"
  desc  "The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database. The default client/server LDAP application for CentOS is OpenLDAP."
  impact 0.0
  describe package("openldap-servers") do
    it { should_not be_installed  }
  end
  describe package("openldap-clients") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.8_Disable_NFS_and_RPC" do
  title "Disable NFS and RPC"
  desc  "The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network."
  impact 0.0
  describe service("rpcidmapd").runlevels(/.*/) do
    it { should be_disabled  }
  end
  describe service("rpcsvcgssd").runlevels(/.*/) do
    it { should be_disabled  }
  end
  describe service("rpcbind").runlevels(/.*/) do
    it { should be_disabled  }
  end
  describe service("rpcgssd").runlevels(/.*/) do
    it { should be_disabled  }
  end
  describe service("nfslock").runlevels(/.*/) do
    it { should be_disabled  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.9_Remove_DNS_Server" do
  title "Remove DNS Server"
  desc  "The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network."
  impact 0.0
  describe package("bind") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.10_Remove_FTP_Server" do
  title "Remove FTP Server"
  desc  "The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files."
  impact 0.0
  describe package("vsftpd") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.11_Remove_HTTP_Server" do
  title "Remove HTTP Server"
  desc  "HTTP or web servers provide the ability to host web site content. The default HTTP server shipped with CentOS Linux is Apache."
  impact 0.0
  describe package("httpd") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.12_Remove_Dovecot_IMAP_and_POP3_services" do
  title "Remove Dovecot (IMAP and POP3 services)"
  desc  "Dovecot is an open source IMAP and POP3 server for Linux based systems."
  impact 0.0
  describe package("dovecot") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.13_Remove_Samba" do
  title "Remove Samba"
  desc  "The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Server Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems."
  impact 0.0
  describe package("samba") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.14_Remove_HTTP_Proxy_Server" do
  title "Remove HTTP Proxy Server"
  desc  "The default HTTP proxy package shipped with CentOS Linux is squid."
  impact 0.0
  describe package("squid") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.15_Remove_SNMP_Server" do
  title "Remove SNMP Server"
  desc  "The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system."
  impact 0.0
  describe package("net-snmp") do
    it { should_not be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.16_Configure_Mail_Transfer_Agent_for_Local-Only_Mode" do
  title "Configure Mail Transfer Agent for Local-Only Mode"
  desc  "Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail. By default, the MTA is set to loopback mode on CentOS."
  impact 1.0
  describe "SCAP oval resource inetlisteningservers_test is not yet supported." do
    skip "SCAP oval resource inetlisteningservers_test is not yet supported."
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.1_Disable_IP_Forwarding" do
  title "Disable IP Forwarding"
  desc  "The net.ipv4.ip_forward flag is used to tell the server whether it can forward packets or not. If the server is not to be used as a router, set the flag to 0."
  impact 1.0
  describe kernel_parameter("net.ipv4.ip_forward") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.ip_forward") do
    its(:value) { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.2_Disable_Send_Packet_Redirects" do
  title "Disable Send Packet Redirects"
  desc  "ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as a router (in a host only configuration), there is no need to send redirects."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its(:value) { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its(:value) { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1_Disable_Source_Routed_Packet_Acceptance" do
  title "Disable Source Routed Packet Acceptance"
  desc  "In networking, source routing allows a sender to partially or fully specify the route packets take through a network. In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its(:value) { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its(:value) { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2_Disable_ICMP_Redirect_Acceptance" do
  title "Disable ICMP Redirect Acceptance"
  desc  "ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects to 0, the system will not accept any ICMP redirect messages, and therefore, won't allow outsiders to update the system's routing tables."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its(:value) { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_redirects") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_redirects") do
    its(:value) { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.4_Log_Suspicious_Packets" do
  title "Log Suspicious Packets"
  desc  "When enabled, this feature logs packets with un-routable source addresses to the kernel log."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its(:value) { should eq 1 }
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its(:value) { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.5_Enable_Ignore_Broadcast_Requests" do
  title "Enable Ignore Broadcast Requests"
  desc  "Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo and timestamp requests to broadcast and multicast addresses."
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its(:value) { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.6_Enable_Bad_Error_Message_Protection" do
  title "Enable Bad Error Message Protection"
  desc  "Setting icmp_ignore_bogus_error_responses to 1 prevents the the kernel from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from filling up with useless log messages."
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses") do
    its(:value) { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.8_Enable_TCP_SYN_Cookies" do
  title "Enable TCP SYN Cookies"
  desc  "When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that encodes the source and destination IP address and port number and the time the packet was sent. A legitimate connection would send the ACK packet of the three way handshake with the specially crafted sequence number. This allows the server to verify that it has received a valid response to a SYN cookie and allow the connection, even though there is no corresponding SYN in the queue."
  impact 1.0
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its(:value) { should_not be_nil  }
  end
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its(:value) { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.3.1_Deactivate_Wireless_Interfaces" do
  title "Deactivate Wireless Interfaces"
  desc  "Wireless networking is used when wired networks are unavailable. CentOS contains a wireless tool kit to allow system administrators to configure and use wireless networks."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.4.1.1_Disable_IPv6_Router_Advertisements" do
  title "Disable IPv6 Router Advertisements"
  desc  "This setting disables the systems ability to accept router advertisements"
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.4.1.2_Disable_IPv6_Redirect_Acceptance" do
  title "Disable IPv6 Redirect Acceptance"
  desc  "This setting prevents the system from accepting ICMP redirects. ICMP redirects tell the system about alternate routes for sending traffic."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.4.2_Disable_IPv6" do
  title "Disable IPv6"
  desc  "Although IPv6 has many advantages over IPv4, few organizations have implemented IPv6."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.1_Install_TCP_Wrappers" do
  title "Install TCP Wrappers"
  desc  "TCP Wrappers provides a simple access list and standardized logging method for services capable of supporting it. In the past, services that were called from inetd and xinetd supported the use of tcp wrappers. As inetd and xinetd have been falling in disuse, any service that can support tcp wrappers will have the libwrap.so library attached to it."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.2_Create_etchosts.allow" do
  title "Create /etc/hosts.allow"
  desc  "The /etc/hosts.allow file specifies which IP addresses are permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.deny file."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.3_Verify_Permissions_on_etchosts.allow" do
  title "Verify Permissions on /etc/hosts.allow"
  desc  "The /etc/hosts.allow file contains networking information that is used by many applications and therefore must be readable for these applications to operate."
  impact 1.0
  describe file("/etc/hosts.allow") do
    it { should exist  }
  end
  describe file("/etc/hosts.allow") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.4_Create_etchosts.deny" do
  title "Create /etc/hosts.deny"
  desc  "The /etc/hosts.deny file specifies which IP addresses are not permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.allow file."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.5.5_Verify_Permissions_on_etchosts.deny" do
  title "Verify Permissions on /etc/hosts.deny"
  desc  "The /etc/hosts.deny file contains network information that is used by many system applications and therefore must be readable for these applications to operate."
  impact 1.0
  describe file("/etc/hosts.deny") do
    it { should exist  }
  end
  describe file("/etc/hosts.deny") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.6.1_Disable_DCCP" do
  title "Disable DCCP"
  desc  "The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports streaming media and telephony. DCCP provides a way to gain access to congestion control, without having to do it at the application layer, but does not provide in-sequence delivery."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.6.2_Disable_SCTP" do
  title "Disable SCTP"
  desc  "The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support message oriented communication, with several streams of messages in one connection. It serves a similar function as TCP and UDP, incorporating features of both. It is message-oriented like UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.6.3_Disable_RDS" do
  title "Disable RDS"
  desc  "The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide low-latency, high-bandwidth communications between cluster nodes. It was developed by the Oracle Corporation."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.6.4_Disable_TIPC" do
  title "Disable TIPC"
  desc  "The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communication between cluster nodes."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.7_Enable_IPtables" do
  title "Enable IPtables"
  desc  "IPtables is an application that allows a system administrator to configure the IPv4 tables, chains and rules provided by the Linux kernel firewall."
  impact 1.0
  describe service("iptables").runlevels(/.*/) do
    it { should_not be_empty  }
  end
  describe service("iptables").runlevels(/.*/) do
    it { should be_enabled  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.8_Enable_IP6tables" do
  title "Enable IP6tables"
  desc  "IP6tables is an application that allows a system administrator to configure the IPv6 tables, chains and rules provided by the Linux kernel firewall."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.1_Install_the_rsyslog_package" do
  title "Install the rsyslog package"
  desc  "The rsyslog package is a third party package that provides many enhancements to syslog, such as multi-threading, TCP communication, message filtering and data base support."
  impact 1.0
  describe package("rsyslog") do
    it { should be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.2_Activate_the_rsyslog_Service" do
  title "Activate the rsyslog Service"
  desc  "The chkconfig command can be used to ensure that the syslog service is turned off and that the rsyslog service is turned on."
  impact 1.0
  describe service("syslog").runlevels(/.*/) do
    it { should be_disabled  }
  end
  describe service("rsyslog").runlevels(/.*/) do
    it { should_not be_empty  }
  end
  describe service("rsyslog").runlevels(/.*/) do
    it { should be_enabled  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.3_Configure_etcrsyslog.conf" do
  title "Configure /etc/rsyslog.conf"
  desc  "The /etc/rsyslog.conf file specifies rules for logging and which files are to be used to log certain classes of messages."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.4_Create_and_Set_Permissions_on_rsyslog_Log_Files" do
  title "Create and Set Permissions on rsyslog Log Files"
  desc  "A log file must already exist for rsyslog to be able to write to it."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.5_Configure_rsyslog_to_Send_Logs_to_a_Remote_Log_Host" do
  title "Configure rsyslog to Send Logs to a Remote Log Host"
  desc  "The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or to receive messages from remote hosts, reducing administrative overhead."
  impact 1.0
  describe file("/etc/rsyslog.conf") do
    its(:content) { should match /^\*\.\*\s+@/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.6_Accept_Remote_rsyslog_Messages_Only_on_Designated_Log_Hosts" do
  title "Accept Remote rsyslog Messages Only on Designated Log Hosts"
  desc  "By default, rsyslog does not listen for log messages coming in from remote systems. The ModLoad tells rsyslog to load the imtcp.so module so it can listen over a network via TCP. The InputTCPServerRun option instructs rsyslogd to listen on the specified TCP port."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3_Configure_logrotate" do
  title "Configure logrotate"
  desc  "The system includes the capability of rotating log files regularly to avoid filling up the system with logs or making the logs unmanageable large. The file /etc/logrotate.d/syslog is the configuration file used to rotate log files created by syslog or rsyslog. These files are rotated on a weekly basis via a cron job and the last 4 weeks are kept."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.1_Enable_anacron_Daemon" do
  title "Enable anacron Daemon"
  desc  "The anacron daemon is used on systems that are not up 24x7. The anacron daemon will execute jobs that would have normally been run had the system not been down."
  impact 1.0
  describe package("cronie-anacron") do
    it { should be_installed  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.2_Enable_crond_Daemon" do
  title "Enable crond Daemon"
  desc  "The crond daemon is used to execute batch jobs on the system."
  impact 1.0
  describe service("crond").runlevels(/.*/) do
    it { should_not be_empty  }
  end
  describe service("crond").runlevels(/.*/) do
    it { should be_enabled  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.3_Set_UserGroup_Owner_and_Permission_on_etcanacrontab" do
  title "Set User/Group Owner and Permission on /etc/anacrontab"
  desc  "The /etc/anacrontab file is used by anacron to control its own jobs. The commands in this item make sure that root is the user and group owner of the file and is the only user that can read and write the file."
  impact 1.0
  describe file("/etc/anacrontab") do
    it { should exist  }
  end
  describe file("/etc/anacrontab") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/anacrontab") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/anacrontab") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/anacrontab") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/anacrontab") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/anacrontab") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/anacrontab") do
    it { should exist  }
  end
  describe file("/etc/anacrontab") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/anacrontab") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.4_Set_UserGroup_Owner_and_Permission_on_etccrontab" do
  title "Set User/Group Owner and Permission on /etc/crontab"
  desc  "The /etc/crontab file is used by cron to control its own jobs. The commands in this item make here sure that root is the user and group owner of the file and is the only user that can read and write the file."
  impact 1.0
  describe file("/etc/crontab") do
    it { should exist  }
  end
  describe file("/etc/crontab") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should exist  }
  end
  describe file("/etc/crontab") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/crontab") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.5_Set_UserGroup_Owner_and_Permission_on_etccron.hourly" do
  title "Set User/Group Owner and Permission on /etc/cron.hourly"
  desc  "This directory contains system cron jobs that need to run on an hourly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory."
  impact 1.0
  describe file("/etc/cron.hourly") do
    it { should exist  }
  end
  describe file("/etc/cron.hourly") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should exist  }
  end
  describe file("/etc/cron.hourly") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/cron.hourly") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.6_Set_UserGroup_Owner_and_Permission_on_etccron.daily" do
  title "Set User/Group Owner and Permission on /etc/cron.daily"
  desc  "The /etc/cron.daily directory contains system cron jobs that need to run on a daily basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory."
  impact 1.0
  describe file("/etc/cron.daily") do
    it { should exist  }
  end
  describe file("/etc/cron.daily") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should exist  }
  end
  describe file("/etc/cron.daily") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/cron.daily") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.7_Set_UserGroup_Owner_and_Permission_on_etccron.weekly" do
  title "Set User/Group Owner and Permission on /etc/cron.weekly"
  desc  "The /etc/cron.weekly directory contains system cron jobs that need to run on a weekly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory."
  impact 1.0
  describe file("/etc/cron.weekly") do
    it { should exist  }
  end
  describe file("/etc/cron.weekly") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should exist  }
  end
  describe file("/etc/cron.weekly") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/cron.weekly") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.8_Set_UserGroup_Owner_and_Permission_on_etccron.monthly" do
  title "Set User/Group Owner and Permission on /etc/cron.monthly"
  desc  "The /etc/cron.monthly directory contains system cron jobs that need to run on a monthly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory."
  impact 1.0
  describe file("/etc/cron.monthly") do
    it { should exist  }
  end
  describe file("/etc/cron.monthly") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should exist  }
  end
  describe file("/etc/cron.monthly") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/cron.monthly") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.9_Set_UserGroup_Owner_and_Permission_on_etccron.d" do
  title "Set User/Group Owner and Permission on /etc/cron.d"
  desc  "The /etc/cron.d directory contains system cron jobs that need to run in a similar manner to the hourly, daily weekly and monthly jobs from /etc/crontab, but require more granular control as to when they run. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory."
  impact 1.0
  describe file("/etc/cron.d") do
    it { should exist  }
  end
  describe file("/etc/cron.d") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should exist  }
  end
  describe file("/etc/cron.d") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/cron.d") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.10_Restrict_at_Daemon" do
  title "Restrict at Daemon"
  desc  "The at daemon works with the cron daemon to allow non-privileged users to submit one time only jobs at their convenience. There are two files that control at: /etc/at.allow and /etc/at.deny. If /etc/at.allow exists, then users listed in the file are the only ones that can create at jobs. If /etc/at.allow does not exist and /etc/at.deny does exist, then any user on the system, with the exception of those listed in /etc/at.deny, are allowed to execute at jobs. An empty /etc/at.deny file allows any user to create at jobs. If neither /etc/at.allow nor /etc/at.deny exist, then only superuser can create at jobs. The commands below remove the /etc/at.deny file and create an empty /etc/at.allow file that can only be read and modified by user and group root."
  impact 1.0
  describe file("/etc/at.deny") do
    it { should_not exist  }
  end
  describe file("/etc/at.allow") do
    it { should exist  }
  end
  describe file("/etc/at.allow") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should exist  }
  end
  describe file("/etc/at.allow") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/at.allow") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.11_Restrict_atcron_to_Authorized_Users" do
  title "Restrict at/cron to Authorized Users"
  desc  "Configure /etc/cron.allow and /etc/at.allow to allow specific users to use these services. If /etc/cron.allow or /etc/at.allow do not exist, then /etc/at.deny and /etc/cron.deny are checked. Any user not specifically defined in those files is allowed to use at and cron. By removing the files, only users in /etc/cron.allow and /etc/at.allow are allowed to use at and cron. Note that even though a given user is not listed in cron.allow, cron jobs can still be run as that user. The cron.allow file only controls administrative access to the crontab command for scheduling and modifying cron jobs."
  impact 1.0
  describe file("/etc/cron.deny") do
    it { should_not exist  }
  end
  describe file("/etc/cron.allow") do
    it { should exist  }
  end
  describe file("/etc/cron.allow") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should exist  }
  end
  describe file("/etc/cron.allow") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/cron.allow") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.1_Set_SSH_Protocol_to_2" do
  title "Set SSH Protocol to 2"
  desc  "SSH supports two different and incompatible protocols: SSH1 and SSH2. SSH1 was the original protocol and was subject to security issues. SSH2 is more advanced and secure."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*Protocol\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*Protocol\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    it { should eq "2" }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.2_Set_LogLevel_to_INFO" do
  title "Set LogLevel to INFO"
  desc  "The INFO parameter specifices that record login and logout activity will be logged."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*LogLevel\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*LogLevel\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    it { should eq "INFO" }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.3_Set_Permissions_on_etcsshsshd_config" do
  title "Set Permissions on /etc/ssh/sshd_config"
  desc  "The /etc/ssh/sshd_config file contains configuration specifications for sshd. The command below sets the owner and group of the file to root."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    it { should exist  }
  end
  describe file("/etc/ssh/sshd_config") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/ssh/sshd_config") do
    its(:uid) { should cmp 0 }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should exist  }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.4_Disable_SSH_X11_Forwarding" do
  title "Disable SSH X11 Forwarding"
  desc  "The X11Forwarding parameter provides the ability to tunnel X11 traffic through the connection to enable remote graphic connections."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*X11Forwarding\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*X11Forwarding\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    it { should eq "no" }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.5_Set_SSH_MaxAuthTries_to_4_or_Less" do
  title "Set SSH MaxAuthTries to 4 or Less"
  desc  "The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. When the login failure count reaches half the number, error messages will be written to the syslog file detailing the login failure."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*MaxAuthTries\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*MaxAuthTries\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    its(:to_i) { should be <= 4  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.6_Set_SSH_IgnoreRhosts_to_Yes" do
  title "Set SSH IgnoreRhosts to Yes"
  desc  "The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*IgnoreRhosts\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*IgnoreRhosts\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    it { should eq "yes" }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.7_Set_SSH_HostbasedAuthentication_to_No" do
  title "Set SSH HostbasedAuthentication to No"
  desc  "The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user of .rhosts, or /etc/hosts.equiv, along with successful public key client host authentication. This option only applies to SSH Protocol Version 2."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*HostbasedAuthentication\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*HostbasedAuthentication\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    it { should eq "no" }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.8_Disable_SSH_Root_Login" do
  title "Disable SSH Root Login"
  desc  "The PermitRootLogin parameter specifies if the root user can log in using ssh(1). The default is no."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*PermitRootLogin\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitRootLogin\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    it { should eq "no" }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.9_Set_SSH_PermitEmptyPasswords_to_No" do
  title "Set SSH PermitEmptyPasswords to No"
  desc  "The PermitEmptyPasswords parameter specifies if the server allows login to accounts with empty password strings."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*PermitEmptyPasswords\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitEmptyPasswords\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    it { should eq "no" }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.10_Do_Not_Allow_Users_to_Set_Environment_Options" do
  title "Do Not Allow Users to Set Environment Options"
  desc  "The PermitUserEnvironment option allows users to present environment options to the ssh daemon."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*PermitUserEnvironment\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitUserEnvironment\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    it { should eq "no" }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.11_Use_Only_Approved_Cipher_in_Counter_Mode" do
  title "Use Only Approved Cipher in Counter Mode"
  desc  "This variable limits the types of ciphers that SSH can use during communication."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*Ciphers\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*Ciphers\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    it { should eq "aes128-ctr,aes192-ctr,aes256-ctr" }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.12_Set_Idle_Timeout_Interval_for_User_Login" do
  title "Set Idle Timeout Interval for User Login"
  desc  "The two options ClientAliveInterval and ClientAliveCountMax control the timeout of ssh sessions. When the ClientAliveInterval variable is set, ssh sessions that have no activity for the specified length of time are terminated. When the ClientAliveCountMax variable is set, sshd will send client alive messages at every ClientAliveInterval interval. When the number of consecutive client alive messages are sent with no response from the client, the ssh session is terminated. For example, if the ClientAliveInterval is set to 15 seconds and the ClientAliveCountMax is set to 3, the client ssh session will be terminated after 45 seconds of idle time."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*ClientAliveInterval\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveInterval\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    its(:to_i) { should be == 300  }
  end
  end
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*ClientAliveCountMax\s+(\S+)\s*(?:#.*)?$/ }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveCountMax\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
    its(:to_i) { should be == 0  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.13_Limit_Access_via_SSH" do
  title "Limit Access via SSH"
  desc  "There are several options available to limit which users and group can access the system via SSH. It is recommended that at least of the following options be leveraged:\n               \n                  \n                     AllowUsers\n                  \n               \n               The AllowUsers variable gives the system administrator the option of allowing specific users to ssh into the system. The list consists of comma separated user names. Numeric userIDs are not recognized with this variable. If a system administrator wants to restrict user access further by only allowing the allowed users to log in from a particular host, the entry can be specified in the form of user@host.\n               \n                  \n                     AllowGroups\n                  \n               \n               The AllowGroups variable gives the system administrator the option of allowing specific groups of users to ssh into the system. The list consists of comma separated user names. Numeric groupIDs are not recognized with this variable.\n               \n                  \n                     DenyUsers\n                  \n               \n               The DenyUsers variable gives the system administrator the option of denying specific users to ssh into the system. The list consists of comma separated user names. Numeric userIDs are not recognized with this variable. If a system administrator wants to restrict user access further by specifically denying a user's access from a particular host, the entry can be specified in the form of user@host.\n               \n                  \n                     DenyGroups\n                  \n               \n               The DenyGroups variable gives the system administrator the option of denying specific groups of users to ssh into the system. The list consists of comma separated group names. Numeric groupIDs are not recognized with this variable."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\s+/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.14_Set_SSH_Banner" do
  title "Set SSH Banner"
  desc  "The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. By default, no banner is displayed."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its(:content) { should match /^\s*Banner\s+(\S+)\s*(?:#.*)?$/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.3.1_Upgrade_Password_Hashing_Algorithm_to_SHA-512" do
  title "Upgrade Password Hashing Algorithm to SHA-512"
  desc  "The commands below change password encryption from md5 to sha512 (a much stronger hashing algorithm). All existing accounts will need to perform a password change to upgrade the stored hashes to the new algorithm."
  impact 1.0
  describe file("/etc/libuser.conf") do
    its(:content) { should match /^[\s]*crypt_style[\s]+=[\s]+(?i)sha512[\s]*$/ }
  end
  describe file("/etc/login.defs") do
    its(:content) { should match /^[\s]*ENCRYPT_METHOD[\s]+SHA512[\s]*$/ }
  end
  describe file("/etc/pam.d/system-auth") do
    its(:content) { should match /^[\s]*password[\s]+(?:(?:required)|(?:sufficient))[\s]+pam_unix\.so[\s]+.*sha512.*$/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.3.2_Set_Password_Creation_Requirement_Parameters_Using_pam_cracklib" do
  title "Set Password Creation Requirement Parameters Using pam_cracklib"
  desc  "The pam_cracklib module checks of the strength of passwords. It performs checks such as making sure a password is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. The following are definitions of the pam_cracklib.so options.\n               \n                  \n                     try_first_pass - retrieve the password from a previous stacked PAM module. If not available, then prompt the user for a password.\n                  \n                     \n                        retry=3\n                     - Allow 3 tries before sending back a failure.\n                  \n                     minlen=14 - password must be 14 characters or more\n                  \n                     dcredit=-1 - provide at least 1 digit\n                  \n                     ucredit=-1 - provide at least one uppercase character\n                  \n                     ocredit=-1 - provide at least one special character\n                  \n                     lcredit=-1 - provide at least one lowercase character\n               \n               The setting shown above is one possible policy. Alter these values to conform to your own organization's password policies."
  impact 1.0
  describe file("/etc/pam.d/system-auth") do
    its(:content) { should match /^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*try_first_pass(=-?\d+)?(?:\s+\S+)*\s*$/ }
  end
  describe file("/etc/pam.d/system-auth") do
    its(:content) { should match /^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*retry=(-?\d+)(?:\s+\S+)*\s*$/ }
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*retry=(-?\d+)(?:\s+\S+)*\s*$/).flatten.each do |entry|
    describe entry do
    its(:to_i) { should be <= 3  }
  end
  end
  describe file("/etc/pam.d/system-auth") do
    its(:content) { should match /^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*minlen=(-?\d+)(?:\s+\S+)*\s*$/ }
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*minlen=(-?\d+)(?:\s+\S+)*\s*$/).flatten.each do |entry|
    describe entry do
    its(:to_i) { should be >= 14  }
  end
  end
  describe file("/etc/pam.d/system-auth") do
    its(:content) { should match /^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*dcredit=(-?\d+)(?:\s+\S+)*\s*$/ }
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*dcredit=(-?\d+)(?:\s+\S+)*\s*$/).flatten.each do |entry|
    describe entry do
    its(:to_i) { should be <= -1  }
  end
  end
  describe file("/etc/pam.d/system-auth") do
    its(:content) { should match /^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*ucredit=(-?\d+)(?:\s+\S+)*\s*$/ }
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*ucredit=(-?\d+)(?:\s+\S+)*\s*$/).flatten.each do |entry|
    describe entry do
    its(:to_i) { should be <= -1  }
  end
  end
  describe file("/etc/pam.d/system-auth") do
    its(:content) { should match /^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*ocredit=(-?\d+)(?:\s+\S+)*\s*$/ }
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*ocredit=(-?\d+)(?:\s+\S+)*\s*$/).flatten.each do |entry|
    describe entry do
    its(:to_i) { should be <= -1  }
  end
  end
  describe file("/etc/pam.d/system-auth") do
    its(:content) { should match /^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*lcredit=(-?\d+)(?:\s+\S+)*\s*$/ }
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:required|requisite)\s+pam_cracklib.so\s+(?:\S+\s+)*lcredit=(-?\d+)(?:\s+\S+)*\s*$/).flatten.each do |entry|
    describe entry do
    its(:to_i) { should be <= -1  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.3.3_Set_Lockout_for_Failed_Password_Attempts" do
  title "Set Lockout for Failed Password Attempts"
  desc  "Lock out userIDs after n unsuccessful consecutive login attempts. The first sets of changes are made to the main PAM configuration files /etc/pam.d/system-auth and /etc/pam.d/password-auth. The second set of changes are applied to the program specific PAM configuration file (in this case, the ssh daemon). The second set of changes must be applied to each program that will lock out userID's.\n               Set the lockout number to the policy in effect at your site."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.3.4_Limit_Password_Reuse" do
  title "Limit Password Reuse"
  desc  "The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords."
  impact 1.0
  describe file("/etc/pam.d/system-auth") do
    its(:content) { should match /^\s*password\s+sufficient\s+pam_unix.so(\s+[^\s]+)*\s+remember=5(\s+[^\s]+)*\s*$/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.4_Restrict_root_Login_to_System_Console" do
  title "Restrict root Login to System Console"
  desc  "The file /etc/securetty contains a list of valid terminals that may be logged in directly as root."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.5_Restrict_Access_to_the_su_Command" do
  title "Restrict Access to the su Command"
  desc  "The su command allows a user to run a command or shell as another user. The program has been superseded by sudo, which allows for more granular control over privileged access. Normally, the su command can be executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su, the su command will only allow users in the wheel group to execute su."
  impact 1.0
  describe file("/etc/pam.d/su") do
    its(:content) { should match /^\s*auth\s+required\s+pam_wheel.so\s+use_uid\s*$/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.1.1_Set_Password_Expiration_Days" do
  title "Set Password Expiration Days"
  desc  "The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age. It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 90 days."
  impact 1.0
  describe file("/etc/login.defs") do
    its(:content) { should match /^PASS_MAX_DAYS\s+(90|[1-7][0-9]|[1-9])$/ }
  end
  shadow.users(/.*/).entries.each do |entry|
    describe entry.max_days.first do
    its(:to_i) { should be <= 90  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.1.2_Set_Password_Change_Minimum_Number_of_Days" do
  title "Set Password Change Minimum Number of Days"
  desc  "The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to prevent users from changing their password until a minimum number of days have passed since the last time the user changed their password. It is recommended that PASS_MIN_DAYS parameter be set to 7 or more days."
  impact 1.0
  describe file("/etc/login.defs") do
    its(:content) { should match /^PASS_MIN_DAYS\s+([7-9]|[1-9][0-9]+)$/ }
  end
  shadow.users(/.*/).entries.each do |entry|
    describe entry.min_days.first do
    its(:to_i) { should be >= 7  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.1.3_Set_Password_Expiring_Warning_Days" do
  title "Set Password Expiring Warning Days"
  desc  "The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users that their password will expire in a defined number of days. It is recommended that the PASS_WARN_AGE parameter be set to 7 or more days."
  impact 1.0
  describe file("/etc/login.defs") do
    its(:content) { should match /^PASS_WARN_AGE\s+([7-9]|[1-9][0-9]+)$/ }
  end
  shadow.users(/.*/).entries.each do |entry|
    describe entry.warn_days.first do
    its(:to_i) { should be >= 7  }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.2_Disable_System_Accounts" do
  title "Disable System Accounts"
  desc  "There are a number of accounts provided with CentOS that are used to manage applications and are not intended to provide an interactive shell."
  impact 1.0
  describe passwd.users(/^(?!root|sync|shutdown|halt).*$/) do
    its(:lines) { should_not be_empty  }
  end
  describe passwd.users(/^(?!root|sync|shutdown|halt).*$/).uids({:<==>500}).shells({:!==>"/sbin/nologin"}) do
    its(:lines) { should be_empty  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.3_Set_Default_Group_for_root_Account" do
  title "Set Default Group for root Account"
  desc  "The usermod command can be used to specify which group the root user belongs to. This affects permissions of files that are created by the root user."
  impact 1.0
  describe passwd.users("root") do
    its(:lines) { should_not be_empty  }
  end
  describe passwd.users("root").gids(0) do
    its(:lines) { should_not be_empty  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.4_Set_Default_umask_for_Users" do
  title "Set Default umask for Users"
  desc  "The default umask determines the permissions of files created by users. The user creating the file has the discretion of making their files and directories readable by others via the chmod command. Users who wish to allow their files and directories to be readable by others by default may choose a different default umask by inserting the umask command into the standard shell configuration files (.profile, .cshrc, etc.) in their home directories."
  impact 1.0
  describe file("/etc/bashrc") do
    its(:content) { should match /^\s*umask\s+077\s*$/ }
  end
  describe "SCAP oval resource textfilecontent54_test could not be loaded: Attribute operation is not yet supported for SCAP::OVAL::Objects: textfilecontent54_object/filename" do
    skip "SCAP oval resource textfilecontent54_test could not be loaded: Attribute operation is not yet supported for SCAP::OVAL::Objects: textfilecontent54_object/filename"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_7.5_Lock_Inactive_User_Accounts" do
  title "Lock Inactive User Accounts"
  desc  "User accounts that have been inactive for over a given period of time can be automatically disabled. It is recommended that accounts that are inactive for 35 or more days be disabled."
  impact 1.0
  describe file("/etc/default/useradd") do
    its(:content) { should match /^INACTIVE=35$/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_8.1_Set_Warning_Banner_for_Standard_Login_Services" do
  title "Set Warning Banner for Standard Login Services"
  desc  "The contents of the /etc/issue file are displayed prior to the login prompt on the system's console and serial devices, and also prior to logins via telnet. The contents of the /etc/motd file is generally displayed after all successful logins, no matter where the user is logging in from, but is thought to be less useful because it only provides notification to the user after the machine has been accessed."
  impact 1.0
  describe file("/etc/motd") do
    it { should exist  }
  end
  describe file("/etc/motd") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/motd") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/motd") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/motd") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/motd") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/motd") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/motd") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/motd") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/motd") do
    it { should be_writable.by "owner" }
  end
  describe file("/etc/motd") do
    it { should exist  }
  end
  describe file("/etc/motd") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/motd") do
    its(:uid) { should cmp 0 }
  end
  describe file("/etc/issue") do
    it { should exist  }
  end
  describe file("/etc/issue") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/issue") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/issue") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/issue") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/issue") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/issue") do
    it { should be_writable.by "owner" }
  end
  describe file("/etc/issue") do
    it { should exist  }
  end
  describe file("/etc/issue") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/issue") do
    its(:uid) { should cmp 0 }
  end
  describe file("/etc/issue.net") do
    it { should exist  }
  end
  describe file("/etc/issue.net") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/issue.net") do
    it { should be_writable.by "owner" }
  end
  describe file("/etc/issue.net") do
    it { should exist  }
  end
  describe file("/etc/issue.net") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/issue.net") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_8.2_Remove_OS_Information_from_Login_Warning_Banners" do
  title "Remove OS Information from Login Warning Banners"
  desc  "Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \n               \n               \\m - machine architecture (uname -m)\n               \\r - operating system release (uname -r)\n               \\s - operating system name\n               \\v - operating system version (uname -v)"
  impact 1.0
  describe file("/etc/motd") do
    its(:content) { should_not match /(\\v|\\r|\\m|\\s)/ }
  end
  describe file("/etc/issue") do
    its(:content) { should_not match /(\\v|\\r|\\m|\\s)/ }
  end
  describe file("/etc/issue.net") do
    its(:content) { should_not match /(\\v|\\r|\\m|\\s)/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_8.3_Set_GNOME_Warning_Banner" do
  title "Set GNOME Warning Banner"
  desc  "The GNOME Display Manager is used for login session management. See the manual page gdm(1) for more information. The remediation action for this item sets a warning message for GDM users before they log in."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.2_Verify_Permissions_on_etcpasswd" do
  title "Verify Permissions on /etc/passwd"
  desc  "The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate."
  impact 1.0
  describe file("/etc/passwd") do
    it { should exist  }
  end
  describe file("/etc/passwd") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/passwd") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.3_Verify_Permissions_on_etcshadow" do
  title "Verify Permissions on /etc/shadow"
  desc  "The /etc/shadow file is used to store the information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information."
  impact 1.0
  describe file("/etc/shadow") do
    it { should exist  }
  end
  describe file("/etc/shadow") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/shadow") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/shadow") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/shadow") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/shadow") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/shadow") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.4_Verify_Permissions_on_etcgshadow" do
  title "Verify Permissions on /etc/gshadow"
  desc  "The /etc/gshadow file contains information about group accounts that is critical to the security of those accounts, such as the hashed password and other security information."
  impact 1.0
  describe file("/etc/gshadow") do
    it { should exist  }
  end
  describe file("/etc/gshadow") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/gshadow") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/gshadow") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.5_Verify_Permissions_on_etcgroup" do
  title "Verify Permissions on /etc/group"
  desc  "The /etc/group file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else."
  impact 1.0
  describe file("/etc/group") do
    it { should exist  }
  end
  describe file("/etc/group") do
    it { should be_executable.by "group" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/group") do
    it { should be_writable.by "group" }
  end
  describe file("/etc/group") do
    it { should be_executable.by "other" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/group") do
    it { should be_writable.by "other" }
  end
  describe file("/etc/group") do
    it { should be_executable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.6_Verify_UserGroup_Ownership_on_etcpasswd" do
  title "Verify User/Group Ownership on /etc/passwd"
  desc  "The /etc/passwd file contains a list of all the valid userIDs defined in the system, but not the passwords. The command below sets the owner and group of the file to root."
  impact 1.0
  describe file("/etc/passwd") do
    it { should exist  }
  end
  describe file("/etc/passwd") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/passwd") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.7_Verify_UserGroup_Ownership_on_etcshadow" do
  title "Verify User/Group Ownership on /etc/shadow"
  desc  "The /etc/shadow file contains the one-way cipher text passwords for each user defined in the /etc/passwd file. The command below sets the user and group ownership of the file to root."
  impact 1.0
  describe file("/etc/shadow") do
    it { should exist  }
  end
  describe file("/etc/shadow") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/shadow") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.8_Verify_UserGroup_Ownership_on_etcgshadow" do
  title "Verify User/Group Ownership on /etc/gshadow"
  desc  "The /etc/gshadow file contains information about group accounts that is critical to the security of those accounts, such as the hashed password and other security information."
  impact 1.0
  describe file("/etc/gshadow") do
    it { should exist  }
  end
  describe file("/etc/gshadow") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/gshadow") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.9_Verify_UserGroup_Ownership_on_etcgroup" do
  title "Verify User/Group Ownership on /etc/group"
  desc  "The /etc/group file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else."
  impact 1.0
  describe file("/etc/group") do
    it { should exist  }
  end
  describe file("/etc/group") do
    its(:gid) { should cmp 0 }
  end
  describe file("/etc/group") do
    its(:uid) { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.10_Find_World_Writable_Files" do
  title "Find World Writable Files"
  desc  "Unix-based systems support variable settings to control access to files. World writable files are the least secure. See the chmod(2) man page for more information."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.11_Find_Un-owned_Files_and_Directories" do
  title "Find Un-owned Files and Directories"
  desc  "Sometimes when administrators delete users from the password file they neglect to remove all files owned by those users from the system."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.12_Find_Un-grouped_Files_and_Directories" do
  title "Find Un-grouped Files and Directories"
  desc  "Sometimes when administrators delete users from the password file they neglect to remove all files owned by those users from the system."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.13_Find_SUID_System_Executables" do
  title "Find SUID System Executables"
  desc  "The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SUID program is to enable users to perform functions (such as changing their password) that require root privileges."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.14_Find_SGID_System_Executables" do
  title "Find SGID System Executables"
  desc  "The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SGID program is to enable users to perform functions (such as changing their password) that require root privileges."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.1_Ensure_Password_Fields_are_Not_Empty" do
  title "Ensure Password Fields are Not Empty"
  desc  "An account with an empty password field means that anybody may log in as that user without providing a password."
  impact 1.0
  shadow.users(/.*/).entries.each do |entry|
    describe entry.passwords do
    its(:first) { should match /.+/ }
  end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.2_Verify_No_Legacy__Entries_Exist_in_etcpasswd_File" do
  title "Verify No Legacy \"+\" Entries Exist in /etc/passwd File"
  desc  "The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on CentOS 6 systems, but may exist in files that have been imported from other platforms."
  impact 1.0
  describe file("/etc/passwd") do
    its(:content) { should_not match /^+:/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.3_Verify_No_Legacy__Entries_Exist_in_etcshadow_File" do
  title "Verify No Legacy \"+\" Entries Exist in /etc/shadow File"
  desc  "The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on CentOS 6 systems, but may exist in files that have been imported from other platforms."
  impact 1.0
  describe file("/etc/shadow") do
    its(:content) { should_not match /^+:/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.4_Verify_No_Legacy__Entries_Exist_in_etcgroup_File" do
  title "Verify No Legacy \"+\" Entries Exist in /etc/group File"
  desc  "The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on CentOS 6 systems, but may exist in files that have been imported from other platforms."
  impact 1.0
  describe file("/etc/group") do
    its(:content) { should_not match /^+:/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.5_Verify_No_UID_0_Accounts_Exist_Other_Than_root" do
  title "Verify No UID 0 Accounts Exist Other Than root"
  desc  "Any account with UID 0 has superuser privileges on the system."
  impact 1.0
  describe file("/etc/passwd") do
    its(:content) { should_not match /^(?!root:)[^:]*:[^:]*:0/ }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.6_Ensure_root_PATH_Integrity" do
  title "Ensure root PATH Integrity"
  desc  "The root user can execute any command on the system and could be fooled into executing programs unemotionally if the PATH is not set correctly."
  impact 1.0
  describe os_env("PATH").content.to_s.split(":") do
    it { should_not be_empty  }
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe entry do
    it { should_not eq "" }
  end
  end
  describe os_env("PATH").content.to_s.split(":") do
    it { should_not be_empty  }
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe entry do
    it { should_not eq "." }
  end
  end
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.7_Check_Permissions_on_User_Home_Directories" do
  title "Check Permissions on User Home Directories"
  desc  "While the system administrator can establish secure permissions for users' home directories, the users can easily override these."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.8_Check_User_Dot_File_Permissions" do
  title "Check User Dot File Permissions"
  desc  "While the system administrator can establish secure permissions for users' \"dot\" files, the users can easily override these."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.9_Check_Permissions_on_User_.netrc_Files" do
  title "Check Permissions on User .netrc Files"
  desc  "While the system administrator can establish secure permissions for users' .netrc files, the users can easily override these."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.10_Check_for_Presence_of_User_.rhosts_Files" do
  title "Check for Presence of User .rhosts Files"
  desc  "While no .rhosts files are shipped with CentOS 6, users can easily create them."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.11_Check_Groups_in_etcpasswd" do
  title "Check Groups in /etc/passwd"
  desc  "Over time, system administration errors and changes can lead to groups being defined in /etc/passwd but not in /etc/group."
  impact 1.0
  describe "SCAP oval resource textfilecontent54_test could not be loaded: Cannot handle referenced value group in textfilecontent54_test; only single values are support at the moment" do
    skip "SCAP oval resource textfilecontent54_test could not be loaded: Cannot handle referenced value group in textfilecontent54_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.12_Check_That_Users_Are_Assigned_Valid_Home_Directories" do
  title "Check That Users Are Assigned Valid Home Directories"
  desc  "Users can be defined in /etc/passwd without a home directory or with a home directory does not actually exist."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.13_Check_User_Home_Directory_Ownership" do
  title "Check User Home Directory Ownership"
  desc  "The user home directory is space defined for the particular user to set local environment variables and to store personal files."
  impact 1.0
  describe "SCAP oval resource invalidhomedirownership_test is not yet supported." do
    skip "SCAP oval resource invalidhomedirownership_test is not yet supported."
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.14_Check_for_Duplicate_UIDs" do
  title "Check for Duplicate UIDs"
  desc  "Although the useradd program will not let you create a duplicate User ID (UID), it is possible for an administrator to manually edit the /etc/passwd file and change the UID field."
  impact 1.0
  describe passwd.users(/.*/).lines do
    its(:length) { should_not be_empty  }
  end
  a = passwd.users(/.*/).lines.uniq.length
  describe passwd.users(/.*/).lines.length do
    its(:to_i) { should be == a  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.15_Check_for_Duplicate_GIDs" do
  title "Check for Duplicate GIDs"
  desc  "Although the groupadd program will not let you create a duplicate Group ID (GID), it is possible for an administrator to manually edit the /etc/group file and change the GID field."
  impact 1.0
  describe file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten do
    its(:length) { should_not be_empty  }
  end
  a = file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten.uniq.length
  describe file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten.length do
    its(:to_i) { should be == a  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.16_Check_for_Duplicate_User_Names" do
  title "Check for Duplicate User Names"
  desc  "Although the useradd program will not let you create a duplicate user name, it is possible for an administrator to manually edit the /etc/passwd file and change the user name."
  impact 1.0
  describe passwd.users(/.*/).lines do
    its(:length) { should_not be_empty  }
  end
  a = passwd.users(/.*/).lines.uniq.length
  describe passwd.users(/.*/).lines.length do
    its(:to_i) { should be == a  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.17_Check_for_Duplicate_Group_Names" do
  title "Check for Duplicate Group Names"
  desc  "Although the groupadd program will not let you create a duplicate group name, it is possible for an administrator to manually edit the /etc/group file and change the group name."
  impact 1.0
  describe file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten do
    its(:length) { should_not be_empty  }
  end
  a = file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten.uniq.length
  describe file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten.length do
    its(:to_i) { should be == a  }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.18_Check_for_Presence_of_User_.netrc_Files" do
  title "Check for Presence of User .netrc Files"
  desc  "The .netrc file contains data for logging into a remote host for file transfers via FTP."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.19_Check_for_Presence_of_User_.forward_Files" do
  title "Check for Presence of User .forward Files"
  desc  "The .forward file specifies an email address to forward the user's mail to."
  impact 1.0
  describe "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment" do
    skip "SCAP oval resource file_test could not be loaded: Cannot handle referenced value group in file_test; only single values are support at the moment"
  end
end