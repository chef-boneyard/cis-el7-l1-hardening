# Cookbook Name:: sa-hardening
# Recipe:: enable_cron
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

# xccdf_org.cisecurity.benchmarks_rule_6.1.1_Enable_anacron_Daemon
# xccdf_org.cisecurity.benchmarks_rule_6.1.2_Enable_crond_Daemon
case node["platform_family"]
when 'rhel'
  if node['platform_version'].to_f >= 7.0

    package 'Install cronie' do
      package_name 'cronie'
      action :install
    end

    package 'Install cronie-anacron' do
      package_name 'cronie-anacron'
      action :install
    end

    package 'Install crontabs' do
      package_name 'crontabs.noarch'
      action :install
    end

    service 'crond' do
      provider Chef::Provider::Service::Systemd
      action [:disable, :stop]
    end

  end
end
