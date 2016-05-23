# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: grub
#
# Copyright (c) 2016 The Authors, All Rights Reserved.


# Start fix for xccdf_org.cisecurity.benchmarks_rule_1.5.2_Set_Permissions_on_bootgrub2grub.cfg
package 'Install grub2' do
  package_name 'grub2'
  action :install
end

file '/boot/grub2/grub.cfg' do
  mode '0600'
  owner 'root'
  group 'root'
  action :create
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_1.5.2_Set_Permissions_on_bootgrub2grub.cfg
