#
# Cookbook Name:: sa-hardening
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
