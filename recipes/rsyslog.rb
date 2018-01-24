# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: rsyslog
#

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

# xccdf_org.cisecurity.benchmarks_rule_4.2.1.3_Ensure_rsyslog_default_file_permissions_configured
replace_or_add 'Ensure rsyslog default file permissions configured' do
  path '/etc/rsyslog.conf'
  pattern '\$FileCreateMode'
  line '$FileCreateMode 0600'
  notifies :restart, 'service[rsyslog.service]', :immediately
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_4.2.1.3_Ensure_rsyslog_default_file_permissions_configured
