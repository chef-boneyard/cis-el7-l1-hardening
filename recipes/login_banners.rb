# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: login_banners
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

case node['platform_family']
when 'rhel'

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_8.2_Remove_OS_Information_from_Login_Warning_Banners
  ['/etc/motd', '/etc/issue', '/etc/issue.net'].each do |loginfile|
    file loginfile do
      mode 0644
      owner 'root'
      group 'root'
      action :create
    end

    execute "Delete OS Version from #{loginfile}" do
      command "/usr/bin/sed -i 's/\\\\v/REDACTED_OSVER/g' #{loginfile}"
      not_if "/usr/bin/grep REDACTED_OSVER #{loginfile}"
      only_if "/usr/bin/grep '\\\\v' #{loginfile}"
    end

    execute "Delete Kernel Version from #{loginfile}" do
      command "/usr/bin/sed -i 's:\\\\r:REDACTED_KERNELVER:g' #{loginfile}"
      not_if "/usr/bin/grep REDACTED_KERNELVER #{loginfile}"
      only_if "/usr/bin/grep '\\\\r' #{loginfile}"
    end

    execute "Delete Machine Architecture from #{loginfile}" do
      command "/usr/bin/sed -i 's/\\\\m/REDACTED_ARCH/g' #{loginfile}"
      not_if "/usr/bin/grep REDACTED_ARCH #{loginfile}"
      only_if "/usr/bin/grep '\\\\m' #{loginfile}"
    end

    execute "Delete OS used from #{loginfile}" do
      command "/usr/bin/sed -i 's/\\\\s/REDACTED_OS/g' #{loginfile}"
      not_if "/usr/bin/grep REDACTED_OS #{loginfile}"
      only_if "/usr/bin/grep '\\\\s' #{loginfile}"
    end
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_8.2_Remove_OS_Information_from_Login_Warning_Banners
end
