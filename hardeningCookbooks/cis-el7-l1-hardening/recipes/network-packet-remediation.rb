# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: network-packet-remediation
#
# Copyright (c) 2016 The Authors, All Rights Reserved.


# Addresses Log Suspicious Packets
case node["platform_family"]
when 'rhel'
  replace_or_add "enable_update_net.ipv4.conf.all.log_martians=1" do
    path "/etc/sysctl.conf"
    pattern "net.ipv4.conf.all.log_martians"
    line "net.ipv4.conf.all.log_martians=1"
  end
  replace_or_add "enable_net.ipv4.conf.default.log_martians=1" do
    path "/etc/sysctl.conf"
    pattern "net.ipv4.conf.default.log_martians"
    line "net.ipv4.conf.default.log_martians=1"
  end
  execute "update_net.ipv4.conf.all.log_martians=1" do
    command "/sbin/sysctl -w net.ipv4.conf.all.log_martians=1"
    not_if '/sbin/sysctl -q -n net.ipv4.conf.all.log_martians | /usr/bin/grep 1'
  end
  execute "update_net.ipv4.conf.default.log_martians=1" do
    command "/sbin/sysctl -w net.ipv4.conf.default.log_martians=1"
    not_if '/sbin/sysctl -q -n net.ipv4.conf.default.log_martians | /usr/bin/grep 1'
  end
end



# Addresses Send Packet Redirects
case node["platform_family"]
when 'rhel'
  replace_or_add "enable_net.ipv4.conf.all.send_redirects=0" do
    path "/etc/sysctl.conf"
    pattern "net.ipv4.conf.all.send_redirects"
    line "net.ipv4.conf.all.send_redirects=0"
  end
  replace_or_add "enable_net.ipv4.conf.default.send_redirects=0" do
    path "/etc/sysctl.conf"
    pattern "net.ipv4.conf.default.send_redirects"
    line "net.ipv4.conf.default.send_redirects=0"
  end
  execute "update_net.ipv4.conf.all.send_redirects=0" do
    command "/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0"
    not_if '/sbin/sysctl -q -n net.ipv4.conf.all.send_redirects | /usr/bin/grep 0'
  end
  execute "update_net.ipv4.conf.default.send_redirects=0" do
    command "/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0"
    not_if '/sbin/sysctl -q -n net.ipv4.conf.default.send_redirects | /usr/bin/grep 0'
  end
end

#Addresses ICMP Redirect Acceptance
case node["platform_family"]
when 'rhel'
  replace_or_add "enable_net.ipv4.conf.all.accept_redirects=0" do
    path "/etc/sysctl.conf"
    pattern "net.ipv4.conf.all.accept_redirects"
    line "net.ipv4.conf.all.accept_redirects=0"
  end
  replace_or_add "enable_net.ipv4.conf.default.accept_redirects=0" do
    path "/etc/sysctl.conf"
    pattern "net.ipv4.conf.default.accept_redirects"
    line "net.ipv4.conf.default.accept_redirects=0"
  end
  execute "update_net.ipv4.conf.all.accept_redirects=0" do
    command "/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0"
    not_if '/sbin/sysctl -q -n net.ipv4.conf.all.accept_redirects | /usr/bin/grep 0'
  end
  execute "update_net.ipv4.conf.default.accept_redirects=0" do
    command "/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0"
    not_if '/sbin/sysctl -q -n net.ipv4.conf.default.accept_redirects | /usr/bin/grep 0'
  end
end
