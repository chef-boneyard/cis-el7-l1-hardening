#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: user-mgmt
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

case node['platform_family']
when 'rhel'

  # Begin xccdf_org.cisecurity.benchmarks_rule_7.5_Lock_Inactive_User_Accounts
  file '/etc/default/useradd' do
    mode '0644'
    owner 'root'
    group 'root'
    action :create
  end

  replace_or_add 'User Inactive Enforcement' do
    path '/etc/default/useradd'
    pattern 'INACTIVE'
    line 'INACTIVE=35'
  end
  # End xccdf_org.cisecurity.benchmarks_rule_7.5_Lock_Inactive_User_Accounts

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_9.1.2_Verify_Permissions_on_etcpasswd
  file '/etc/passwd' do
    mode '0644'
    owner 'root'
    group 'root'
    action :create
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_9.1.2_Verify_Permissions_on_etcpasswd

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.5_Restrict_Access_to_the_su_Command
  file '/etc/pam.d/su' do
    mode '0644'
    owner 'root'
    group 'root'
    action :create
  end

  replace_or_add 'Restrict su Command' do
    path '/etc/pam.d/su'
    pattern '.*pam_wheel.so use_uid'
    line 'auth            required        pam_wheel.so use_uid'
  end
  # End xccdf_org.cisecurity.benchmarks_rule_6.5_Restrict_Access_to_the_su_Command

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_7.4_Set_Default_umask_for_Users
  file '/etc/bashrc' do
    mode '0644'
    owner 'root'
    group 'root'
    action :create
  end

  replace_or_add 'default umask for /etc/bashrc' do
    path '/etc/bashrc'
    pattern '^\s*umask\s'
    line '    umask 077'
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_7.4_Set_Default_umask_for_Users

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.3.4_Limit_Password_Reuse
  file '/etc/pam.d/system-auth' do
    mode '0644'
    owner 'root'
    group 'root'
    action :create
  end

  replace_or_add 'Limit Password Reusd' do
    path '/etc/pam.d/system-auth'
    pattern 'auth        sufficient    pam_unix.so remember=.*'
    line 'auth        sufficient    pam_unix.so remember=5'
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_6.3.4_Limit_Password_Reuse

end
