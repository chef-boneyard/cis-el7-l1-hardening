# Cookbook Name:: sa-hardening
# Recipe:: restrict_cron
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

case node["platform_family"]
when 'rhel'
  if node['platform_version'].to_f >= 7.0

    file '/etc/cron.deny' do
      action :delete
    end

    file '/etc/cron.allow' do
      action :create
      mode 0700
      owner 0
      group 0
    end

  end
end
