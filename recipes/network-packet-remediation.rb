# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: network-packet-remediation
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

case node['platform_family']
when 'rhel'

  # Ensure package that manages /etc/sysctl.conf is installed
  package 'Install initscripts' do
    package_name 'initscripts'
    action :install
  end

  # Ensure package that installs sysctl binary is installed
  package 'Install procps-ng' do
    package_name 'procps-ng'
    action :install
  end

  # Ensure configuration file is present
  file '/etc/sysctl.conf' do
    mode 0644
    owner 'root'
    group 'root'
    action :create
  end

  # Addresses Log Suspicious Packets
  replace_or_add 'enable_update_net.ipv4.conf.all.log_martians=1' do
    path '/etc/sysctl.conf'
    pattern 'net.ipv4.conf.all.log_martians'
    line 'net.ipv4.conf.all.log_martians=1'
  end
  replace_or_add 'enable_net.ipv4.conf.default.log_martians=1' do
    path '/etc/sysctl.conf'
    pattern 'net.ipv4.conf.default.log_martians'
    line 'net.ipv4.conf.default.log_martians=1'
  end
  execute 'update_net.ipv4.conf.all.log_martians=1' do
    command '/sbin/sysctl -w net.ipv4.conf.all.log_martians=1'
    not_if '/sbin/sysctl -q -n net.ipv4.conf.all.log_martians | /usr/bin/grep 1'
  end
  execute 'update_net.ipv4.conf.default.log_martians=1' do
    command '/sbin/sysctl -w net.ipv4.conf.default.log_martians=1'
    not_if '/sbin/sysctl -q -n net.ipv4.conf.default.log_martians | /usr/bin/grep 1'
  end
  # End

  # Addresses Send Packet Redirects
  replace_or_add 'enable_net.ipv4.conf.all.send_redirects=0' do
    path '/etc/sysctl.conf'
    pattern 'net.ipv4.conf.all.send_redirects'
    line 'net.ipv4.conf.all.send_redirects=0'
  end
  replace_or_add 'enable_net.ipv4.conf.default.send_redirects=0' do
    path '/etc/sysctl.conf'
    pattern 'net.ipv4.conf.default.send_redirects'
    line 'net.ipv4.conf.default.send_redirects=0'
  end
  execute 'update_net.ipv4.conf.all.send_redirects=0' do
    command '/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0'
    not_if '/sbin/sysctl -q -n net.ipv4.conf.all.send_redirects | /usr/bin/grep 0'
  end
  execute 'update_net.ipv4.conf.default.send_redirects=0' do
    command '/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0'
    not_if '/sbin/sysctl -q -n net.ipv4.conf.default.send_redirects | /usr/bin/grep 0'
  end
  # End of Send Packet Redirects

  # Addresses ICMP Redirect Acceptance
  replace_or_add 'enable_net.ipv4.conf.all.accept_redirects=0' do
    path '/etc/sysctl.conf'
    pattern 'net.ipv4.conf.all.accept_redirects'
    line 'net.ipv4.conf.all.accept_redirects=0'
  end
  replace_or_add 'enable_net.ipv4.conf.default.accept_redirects=0' do
    path '/etc/sysctl.conf'
    pattern 'net.ipv4.conf.default.accept_redirects'
    line 'net.ipv4.conf.default.accept_redirects=0'
  end
  execute 'update_net.ipv4.conf.all.accept_redirects=0' do
    command '/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0'
    not_if '/sbin/sysctl -q -n net.ipv4.conf.all.accept_redirects | /usr/bin/grep 0'
  end
  execute 'update_net.ipv4.conf.default.accept_redirects=0' do
    command '/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0'
    not_if '/sbin/sysctl -q -n net.ipv4.conf.default.accept_redirects | /usr/bin/grep 0'
  end
  # End ICMP Redirect Acceptance

end
