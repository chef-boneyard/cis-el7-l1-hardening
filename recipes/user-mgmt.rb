# -*- coding: utf-8 -*-
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

  # Begin xccdf_org.cisecurity.benchmarks_rule_5.4.1.4_Ensure_inactive_password_lock_is_30_days_or_less
  replace_or_add 'User Inactive Enforcement' do
    path '/etc/default/useradd'
    pattern 'INACTIVE'
    line 'INACTIVE=30'
  end
  # End xccdf_org.cisecurity.benchmarks_rule_5.4.1.4_Ensure_inactive_password_lock_is_30_days_or_less
  # End xccdf_org.cisecurity.benchmarks_rule_7.5_Lock_Inactive_User_Accounts

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_9.1.2_Verify_Permissions_on_etcpasswd
  file '/etc/passwd' do
    mode '0644'
    owner 'root'
    group 'root'
    action :create
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_9.1.2_Verify_Permissions_on_etcpasswd

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.1.6_Ensure_permissions_on_etcpasswd-_are_configured
  file '/etc/passwd-' do
    mode '0600'
    owner 'root'
    group 'root'
    action :create
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_6.1.6_Ensure_permissions_on_etcpasswd-_are_configured

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.1.8_Ensure_permissions_on_etcgroup-_are_configured
  file '/etc/group-' do
    mode '0600'
    owner 'root'
    group 'root'
    action :create
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_6.1.8_Ensure_permissions_on_etcgroup-_are_configured

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

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_5.4.4_Ensure_default_user_umask_is_027_or_more_restrictive
  replace_or_add 'default umask for /etc/bashrc' do
    path '/etc/bashrc'
    pattern '^\s*umask\s'
    line '    umask 027'
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_5.4.4_Ensure_default_user_umask_is_027_or_more_restrictive
  # End fix for xccdf_org.cisecurity.benchmarks_rule_7.4_Set_Default_umask_for_Users
end
