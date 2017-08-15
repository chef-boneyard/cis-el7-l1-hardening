# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: rsyslog
#
# Copyright:: 2017, Chef Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
