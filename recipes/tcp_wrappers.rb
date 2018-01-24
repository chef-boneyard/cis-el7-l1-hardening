#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: tcp_wrappers
#
# Copyright (c) 2017 Chef Software

# 3.4.1_Ensure_TCP_Wrappers_is_installed: Ensure TCP Wrappers is installed

package 'Install TCP Wrappers' do
  package_name 'tcp_wrappers'
  action :install
end
