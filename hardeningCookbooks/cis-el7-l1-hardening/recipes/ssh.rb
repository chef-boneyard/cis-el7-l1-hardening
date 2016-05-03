#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: ssh
# Remediation for SSH specific controls
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.1_Set_SSH_Protocol_to_2
replace_or_add "SSH Protocol" do
  path "/etc/ssh/sshd_config"
  pattern "Protocol 1"
  line "Protocol 2"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.1_Set_SSH_Protocol_to_2

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.5_Set_SSH_MaxAuthTries_to_4_or_Less
replace_or_add "SSH MaxAuthTries" do
  path "/etc/ssh/sshd_config"
  pattern "MaxAuthTries.*"
  line "MaxAuthTries 4"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.5_Set_SSH_MaxAuthTries_to_4_or_Less

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.4_Disable_SSH_X11_Forwarding
replace_or_add "Disable SSH X11 Forwarding" do
  path "/etc/ssh/sshd_config"
  pattern "X11Forwarding.*"
  line "X11Forwarding no"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.4_Disable_SSH_X11_Forwarding

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.6_Set_SSH_IgnoreRhosts_to_Yes
replace_or_add "Set SSH IgnoreRhosts to Yes" do
  path "/etc/ssh/sshd_config"
  pattern "IgnoreRhosts.*"
  line "IgnoreRhosts yes"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.6_Set_SSH_IgnoreRhosts_to_Yes

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.14_Set_SSH_Banner
replace_or_add "Set SSH Banner" do
  path "/etc/ssh/sshd_config"
  pattern "Banner.*"
  line "Banner /etc/ssh/sshd-banner"
end

delete_lines "Remove no default banner comment" do
  path "/etc/ssh/sshd_config"
  pattern "# no default banner path"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.6_Set_SSH_IgnoreRhosts_to_Yes

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.9_Set_SSH_PermitEmptyPasswords_to_No
replace_or_add "Set SSH PermitEmptyPasswords to No" do
  path "/etc/ssh/sshd_config"
  pattern "PermitEmptyPasswords.*"
  line "PermitEmptyPasswords no"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.9_Set_SSH_PermitEmptyPasswords_to_No

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.8_Disable_SSH_Root_Login
replace_or_add "Disable SSH Root Login" do
  path "/etc/ssh/sshd_config"
  pattern "PermitRootLogin.*"
  line "PermitRootLogin no"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.8_Disable_SSH_Root_Login

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.7_Set_SSH_HostbasedAuthentication_to_No
replace_or_add "Set SSH HostbasedAuthentication to No" do
  path "/etc/ssh/sshd_config"
  pattern "HostbasedAuthentication.*"
  line "HostbasedAuthentication no"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.7_Set_SSH_HostbasedAuthentication_to_No

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.2_Set_LogLevel_to_INFO
replace_or_add "Set LogLevel to INFO" do
  path "/etc/ssh/sshd_config"
  pattern "LogLevel.*"
  line "LogLevel INFO"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.2_Set_LogLevel_to_INFO

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.12_Set_Idle_Timeout_Interval_for_User_Login
replace_or_add "Set Idle Timeout Interval for User Login - ClientAliveInterval" do
  path "/etc/ssh/sshd_config"
  pattern "ClientAliveInterval.*"
  line "ClientAliveInterval 300"
end

replace_or_add "Set Idle Timeout Interval for User Login - ClientAliveCountMax" do
  path "/etc/ssh/sshd_config"
  pattern "ClientAliveCountMax.*"
  line "ClientAliveCountMax 0"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.12_Set_Idle_Timeout_Interval_for_User_Login

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.10_Do_Not_Allow_Users_to_Set_Environment_Options
replace_or_add "Do Not Allow Users to Set Environment Options" do
  path "/etc/ssh/sshd_config"
  pattern "PermitUserEnvironment.*"
  line "PermitUserEnvironment no"
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.10_Do_Not_Allow_Users_to_Set_Environment_Options

# Begin fix for xccdf_org.cisecurity.benchmarks_rule_6.2.13_Limit_Access_via_SSH
replace_or_add "Set a DenyUsers config up" do
  path "/etc/ssh/sshd_config"
  pattern "DenyUsers.*"
  line "DenyUsers root"
end

replace_or_add "Set a DenyGroups config up" do
  path "/etc/ssh/sshd_config"
  pattern "DenyGroups.*"
  line "DenyGroups root"
end

# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.13_Limit_Access_via_SSH

# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.2.3_Set_Permissions_on_etcsshsshd_config
file '/etc/ssh/sshd_config' do
  action :create
  mode 0600
  owner 0
  group 0
end

# End fix for xccdf_org.cisecurity.benchmarks_rule_6.2.3_Set_Permissions_on_etcsshsshd_config
