# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: network-packet-remediation
#
# Copyright:: 2017, Chef Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
