# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: init
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

# Start fix for xccdf_org.cisecurity.benchmarks_rule_3.1_Set_Daemon_umask
package 'Install initscripts' do
  package_name 'initscripts'
  action :install
end

replace_or_add 'Set Daemon umask' do
  path '/etc/sysconfig/init'
  pattern 'umask 027'
  line 'umask 027'
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_3.1_Set_Daemon_umask
