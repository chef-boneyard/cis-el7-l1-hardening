# Cookbook Name:: sa-hardening
# Recipe:: avahi
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

package 'Install Avahi Autoipd' do
  case node["platform"]
  when 'redhat'
    package_name 'avahi-autoipd'
  end
  action :install
end

package 'Install Avahi Libs' do
  case node["platform"]
  when 'redhat'
    package_name 'avahi-libs'
  end
  action :install
end

package 'Install Avahi' do
  case node["platform"]
  when 'redhat'
    package_name 'avahi'
  end
  action :install
end

service 'avahi-daemon.socket' do
  case node["platform"]
  when 'redhat'
    if node['platform_version'].to_f >= 7.0
      provider Chef::Provider::Service::Systemd
    end
  end
  action [:disable, :stop]
end

service 'avahi-daemon.service' do
  case node["platform"]
  when 'redhat'
    if node['platform_version'].to_f >= 7.0
      provider Chef::Provider::Service::Systemd
    end
  end
  action [:disable, :stop]
end
