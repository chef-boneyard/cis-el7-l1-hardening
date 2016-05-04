# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: rsyslog
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

# Start fix for xccdf_org.cisecurity.benchmarks_rule_5.1.5_Configure_rsyslog_to_Send_Logs_to_a_Remote_Log_Host
package 'Install rsyslog' do
  package_name 'rsyslog'
  action :install
end

service 'rsyslog.service' do
  provider Chef::Provider::Service::Systemd
  action [:enable, :start]
end

replace_or_add 'Configure rsyslog to send logs to remote host' do
  path '/etc/rsyslog.conf'
  pattern '#*.* @@remote-host:514'
  line '*.* @@remote-host:514'
  notifies :restart, 'service[rsyslog.service]', :immediately
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_5.1.5_Configure_rsyslog_to_Send_Logs_to_a_Remote_Log_Host
