# Cookbook Name:: sa-hardening
# Recipe:: user-mgmt
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

case node["platform_family"]
when 'rhel'

# Begin xccdf_org.cisecurity.benchmarks_rule_7.5_Lock_Inactive_User_Accounts
  replace_or_add "User Inactive Enforcement" do
    path "/etc/default/useradd"
    pattern "INACTIVE"
    line "INACTIVE=35"
  end
# End xccdf_org.cisecurity.benchmarks_rule_7.5_Lock_Inactive_User_Accounts

end
