# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: at_daemon
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

# Addresses xccdf_org.cisecurity.benchmarks_rule_6.1.10_Restrict_at_Daemon
case node['platform_family']
when 'rhel'
  if node['platform_version'].to_f >= 7.0

    file '/etc/at.deny' do
      action :delete
    end

    file '/etc/at.allow' do
      action :create
      mode 0700
      owner 'root'
      group 'root'
    end

  end
end
# End xccdf_org.cisecurity.benchmarks_rule_6.1.10_Restrict_at_Daemon
