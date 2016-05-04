# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: avahi
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

case node['platform_family']
when 'rhel'
  if node['platform_version'].to_f >= 7.0
    package 'Install Avahi Libs' do
      package_name 'avahi-libs'
      action :install
    end

    package 'Install Avahi Autoipd' do
      package_name 'avahi-autoipd'
      action :install
    end

    package 'Install Avahi' do
      package_name 'avahi'
      action :install
    end

    service 'avahi-daemon.socket' do
      provider Chef::Provider::Service::Systemd
      action [:disable, :stop]
    end

    service 'avahi-daemon.service' do
      provider Chef::Provider::Service::Systemd
      action [:disable, :stop]
    end

  end
end
