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

# xccdf_org.cisecurity.benchmarks_rule_1.3.2_Ensure_filesystem_integrity_is_regularly_checked:
replace_or_add "Ensure filesystem integrity is regularly checked" do
  path '/etc/crontab'
  pattern 'aide --check'
  line '05 3 * * * root /usr/sbin/aide --check'
end
