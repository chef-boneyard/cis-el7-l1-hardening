#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: default
#
# Copyright (c) 2016 The Authors, All Rights Reserved.
case node['platform_family']
when 'rhel'
  if node['platform_version'].to_f >= 7.0

    # Remiation recipes includes (alphabetical)
    include_recipe 'cis-el7-l1-hardening::at_daemon'
    include_recipe 'cis-el7-l1-hardening::avahi'
    include_recipe 'cis-el7-l1-hardening::core_dumps'
    include_recipe 'cis-el7-l1-hardening::cron'
    include_recipe 'cis-el7-l1-hardening::firewalld'
    include_recipe 'cis-el7-l1-hardening::grub'
    include_recipe 'cis-el7-l1-hardening::init'
    include_recipe 'cis-el7-l1-hardening::login_banners'
    include_recipe 'cis-el7-l1-hardening::network-packet-remediation'
    include_recipe 'cis-el7-l1-hardening::ntp'
    include_recipe 'cis-el7-l1-hardening::rsyslog'
    include_recipe 'cis-el7-l1-hardening::ssh'
    include_recipe 'cis-el7-l1-hardening::user-mgmt'

    # This should be the last recipe thats run as it remediates
    # the shadow file to a CIS compliant standard and prior recipes may have
    # influence additions / removals to the shadow file.
    #
    include_recipe 'cis-el7-l1-hardening::passwords'

  end
end
