# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: cron
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

case node['platform_family']
when 'rhel'
  if node['platform_version'].to_f >= 7.0

    # Begin xccdf_org.cisecurity.benchmarks_rule_6.1.2_Enable_crond_Daemon
    package 'Install cronie' do
      package_name 'cronie'
      action :install
    end

    service 'crond' do
      provider Chef::Provider::Service::Systemd
      action [:enable, :start]
    end
    # End xccdf_org.cisecurity.benchmarks_rule_6.1.2_Enable_crond_Daemon

    # Begin xccdf_org.cisecurity.benchmarks_rule_6.1.1_Enable_anacron_Daemon

    package 'Install cronie-anacron' do
      package_name 'cronie-anacron'
      action :install
    end

    package 'Install crontabs' do
      package_name 'crontabs.noarch'
      action :install
    end
    # End xccdf_org.cisecurity.benchmarks_rule_6.1.1_Enable_anacron_Daemon

    # Start fix for hardening of cronfiles
    ['/etc/cron.d', '/etc/cron.monthly', '/etc/cron.weekly',
     '/etc/cron.daily', '/etc/cron.hourly'].each do |crondir|
      directory crondir do
        mode '0700'
        owner 'root'
        group 'root'
        action :create
      end
    end

    ['/etc/crontab', '/etc/anacrontab'].each do |cronfile|
      file cronfile do
        mode '0700'
        owner 'root'
        group 'root'
        action :create
      end
    end
    # End fix for hardening of cronfiles

    # Begin xccdf_org.cisecurity.benchmarks_rule_6.1.11_Restrict_atcron_to_Authorized_Users
    file '/etc/cron.deny' do
      action :delete
    end

    file '/etc/cron.allow' do
      action :create
      mode 0700
      owner 'root'
      group 'root'
    end
    # End xccdf_org.cisecurity.benchmarks_rule_6.1.11_Restrict_atcron_to_Authorized_Users

  end
end
