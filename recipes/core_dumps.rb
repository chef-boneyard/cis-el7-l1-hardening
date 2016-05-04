# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: core_dumps
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

# Begin xccdf_org.cisecurity.benchmarks_rule_1.6.1_Restrict_Core_Dumps

case node['platform_family']
when 'rhel'

  # Ensure package is installed
  package 'Install pam' do
    package_name 'pam'
    action :install
  end

  replace_or_add 'Restrict Core Dumps' do
    path '/etc/security/limits.conf'
    pattern '^\A\*\shard\score\s0'
    line '* hard core 0'
  end

end

# End xccdf_org.cisecurity.benchmarks_rule_1.6.1_Restrict_Core_Dumps
