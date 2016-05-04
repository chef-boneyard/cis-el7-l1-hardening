#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: enable_sudo_no_tty
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

# Ensure sudo is installed
package 'Install sudo' do
  package_name 'sudo'
  action :install
end

file '/etc/sudoers' do
  mode 0440
  owner 'root'
  group 'root'
  action :create
end

delete_lines 'remove hash-comments from /some/file' do
  path '/etc/sudoers'
  pattern '^.*requiretty'
end
