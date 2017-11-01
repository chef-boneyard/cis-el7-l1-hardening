#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: aide
#
# Copyright (c) 2017 Chef Software

# 1.3.1_Ensure_AIDE_is_installed: Ensure AIDE is installed

package 'Install AIDE' do
  package_name 'aide'
  action :install
end
