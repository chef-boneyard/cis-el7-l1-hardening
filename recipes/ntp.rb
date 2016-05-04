#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: ntp
# Remediation for ntp specific controls
#
# Copyright (c) 2016 The Authors, All Rights Reserved.
# Start fix for xccdf_org.cisecurity.benchmarks_rule_6.5_Configure_Network_Time_Protocol_NTP


# Install Package NTP (also installs ntpd)
case node['platform_family']
when 'rhel'
  if node['platform_version'].to_f >= 7.0
      package 'ntp' do
        package_name 'ntp'
        action :install
      end

    # Create file ntp.conf if not present
    file '/etc/ntp.conf' do
      mode '0644'
      owner 'root'
    end

    # Correct ntp.conf config to conform to:
    # /^\s*restrict\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/
    replace_or_add 'Add kod to default restrict list in ntp.conf for IP V4' do
      path '/etc/ntp.conf'
      pattern "^restrict\sdefault"
      line 'restrict default kod nomodify notrap nopeer noquery'
    end

    # Correct ntp.conf config to conform to:
    # /^\s*restrict\s+-6\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/ }
    replace_or_add 'Add default restrict list in ntp.conf with a -6 for IP V6 activity' do
      path '/etc/ntp.conf'
      pattern "^restrict\s-6\sdefault"
      line 'restrict -6 default kod nomodify notrap nopeer noquery'
    end

    # Create file ntpd if not present
    file '/etc/sysconfig/ntpd' do
      mode '0644'
      owner 'root'
    end

    # Correct ntpd config to conform to:
    # /^\s*OPTIONS="[^"]*-u ntp:ntp[^"]*"\s*(?:#.*)?$/
    replace_or_add 'ntpd' do
      path '/etc/sysconfig/ntpd'
      pattern 'OPTIONS='
      line 'OPTIONS="-u ntp:ntp -p /var/run/ntpd.pid -g"'
    end
  end
end

# End fix for xccdf_org.cisecurity.benchmarks_rule_6.5_Configure_Network_Time_Protocol_NTP
