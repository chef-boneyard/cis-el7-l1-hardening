#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: kernel
#
# Copyright (c) 2017 Chef Software

# 1.1.1.1_Ensure_mounting_of_cramfs_filesystems_is_disabled
execute 'rmmod cramfs' do
  only_if 'lsmod | grep cramfs'
end

file 'blacklist cramfs' do
  path '/etc/modprobe.d/cramfs.conf'
  content 'install cramfs /bin/true'
end
