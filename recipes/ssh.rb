#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: ssh
# Remediation for SSH specific controls
#
# Copyright (c) 2016 The Authors, All Rights Reserved.
case node['platform_family']
when 'rhel'
  if node['platform_version'].to_f >= 7.0

    # Ensure package is present before we start modifying its configuration
    package 'Install OpenSSH Server' do
      package_name 'openssh-server'
      action :install
    end

    service 'sshd.service' do
      provider Chef::Provider::Service::Systemd
      action [:enable, :start]
    end

    # Resource for when a sshd restart is required
    file 'sshd.changed' do
      action :nothing
      path '/tmp/.sshd-changed'
      mode 0600
      owner 'root'
      group 'root'
    end

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.3_Set_Permissions_on_etcsshsshd_config
    file '/etc/ssh/sshd_config' do
      mode 0600
      owner 'root'
      group 'root'
      action :create
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.3_Set_Permissions_on_etcsshsshd_config

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.1_Set_SSH_Protocol_to_2
    replace_or_add 'SSH Protocol' do
      path '/etc/ssh/sshd_config'
      pattern 'Protocol 1'
      line 'Protocol 2'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.1_Set_SSH_Protocol_to_2

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.5_Set_SSH_MaxAuthTries_to_4_or_Less
    replace_or_add 'SSH MaxAuthTries' do
      path '/etc/ssh/sshd_config'
      pattern 'MaxAuthTries.*'
      line 'MaxAuthTries 4'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.5_Set_SSH_MaxAuthTries_to_4_or_Less

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.4_Disable_SSH_X11_Forwarding
    replace_or_add 'Disable SSH X11 Forwarding' do
      path '/etc/ssh/sshd_config'
      pattern 'X11Forwarding.*'
      line 'X11Forwarding no'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.4_Disable_SSH_X11_Forwarding

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.6_Set_SSH_IgnoreRhosts_to_Yes
    replace_or_add 'Set SSH IgnoreRhosts to Yes' do
      path '/etc/ssh/sshd_config'
      pattern 'IgnoreRhosts.*'
      line 'IgnoreRhosts yes'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.6_Set_SSH_IgnoreRhosts_to_Yes

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.14_Set_SSH_Banner
    replace_or_add 'Set SSH Banner' do
      path '/etc/ssh/sshd_config'
      pattern 'Banner.*'
      line 'Banner /etc/ssh/sshd-banner'
      notifies :create, 'file[sshd.changed]', :immediately
    end

    delete_lines 'Remove no default banner comment' do
      path '/etc/ssh/sshd_config'
      pattern '# no default banner path'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.6_Set_SSH_IgnoreRhosts_to_Yes

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.9_Set_SSH_PermitEmptyPasswords_to_No
    replace_or_add 'Set SSH PermitEmptyPasswords to No' do
      path '/etc/ssh/sshd_config'
      pattern 'PermitEmptyPasswords.*'
      line 'PermitEmptyPasswords no'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.9_Set_SSH_PermitEmptyPasswords_to_No

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.8_Disable_SSH_Root_Login
    replace_or_add 'Disable SSH Root Login' do
      path '/etc/ssh/sshd_config'
      pattern 'PermitRootLogin.*'
      line 'PermitRootLogin no'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.8_Disable_SSH_Root_Login

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.7_Set_SSH_HostbasedAuthentication_to_No
    replace_or_add 'Set SSH HostbasedAuthentication to No' do
      path '/etc/ssh/sshd_config'
      pattern 'HostbasedAuthentication.*'
      line 'HostbasedAuthentication no'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.7_Set_SSH_HostbasedAuthentication_to_No

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.2_Set_LogLevel_to_INFO
    replace_or_add 'Set LogLevel to INFO' do
      path '/etc/ssh/sshd_config'
      pattern 'LogLevel.*'
      line 'LogLevel INFO'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.2_Set_LogLevel_to_INFO

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.12_Set_Idle_Timeout_Interval_for_User_Login
    replace_or_add 'Set Idle Timeout Interval for User Login - ClientAliveInterval' do
      path '/etc/ssh/sshd_config'
      pattern 'ClientAliveInterval.*'
      line 'ClientAliveInterval 300'
      notifies :create, 'file[sshd.changed]', :immediately
    end

    replace_or_add 'Set Idle Timeout Interval for User Login - ClientAliveCountMax' do
      path '/etc/ssh/sshd_config'
      pattern 'ClientAliveCountMax.*'
      line 'ClientAliveCountMax 0'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.12_Set_Idle_Timeout_Interval_for_User_Login

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.10_Do_Not_Allow_Users_to_Set_Environment_Options
    replace_or_add 'Do Not Allow Users to Set Environment Options' do
      path '/etc/ssh/sshd_config'
      pattern 'PermitUserEnvironment.*'
      line 'PermitUserEnvironment no'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.10_Do_Not_Allow_Users_to_Set_Environment_Options

    # Begin fix for xccdf_org.cisecurity.benchmarks_rule_6.2.13_Limit_Access_via_SSH
    replace_or_add 'Set a DenyUsers config up' do
      path '/etc/ssh/sshd_config'
      pattern 'DenyUsers.*'
      line 'DenyUsers root'
      notifies :create, 'file[sshd.changed]', :immediately
    end

    replace_or_add 'Set a DenyGroups config up' do
      path '/etc/ssh/sshd_config'
      pattern 'DenyGroups.*'
      line 'DenyGroups root'
      notifies :create, 'file[sshd.changed]', :immediately
    end

    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.13_Limit_Access_via_SSH

    # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.11_Use_Only_Approved_Cipher_in_Counter_Mode
    replace_or_add 'Use Only Approved Cipher in Counter Mode' do
      path '/etc/ssh/sshd_config'
      pattern 'Ciphers.*'
      line 'Ciphers aes128-ctr,aes192-ctr,aes256-ctr'
      notifies :create, 'file[sshd.changed]', :immediately
    end
    # End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.11_Use_Only_Approved_Cipher_in_Counter_Mode

    execute 'Restart sshd only if config has changed' do
      command 'rm -rf /tmp/.sshd-changed'
      only_if 'test -f /tmp/.sshd-changed'
      notifies :restart, 'service[sshd.service]', :immediately
    end

  end
end
