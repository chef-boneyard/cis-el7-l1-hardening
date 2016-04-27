#
# Cookbook Name:: sa-hardening
# Recipe:: default
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

# Fix for "xccdf_org.cisecurity.benchmarks_rule_4.7_Enable_firewalld"

package 'firewalld'

service 'firewalld' do
  supports :status => true
  action [ :enable, :start ]
end

# End fix for "xccdf_org.cisecurity.benchmarks_rule_4.7_Enable_firewalld"

# Start fix for hardening of cronfiles
['/etc/cron.d', '/etc/cron.monthly', '/etc/cron.weekly',
  '/etc/cron.daily', '/etc/cron.hourly'].each do |crondir|
    directory crondir do
      mode '0700'
      owner 'root'
      group 'root'
    end
end

['/etc/crontab', '/etc/anacrontab'].each do |cronfile|
  file cronfile do
    mode '0700'
    owner 'root'
    group 'root'
  end
end
# End fix for hardening of cronfiles
