# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: core_dumps
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

# Begin xccdf_org.cisecurity.benchmarks_rule_1.6.1_Restrict_Core_Dumps
case node['platform_family']
when 'rhel'

  # Ensure package is installed
  package 'Install pam' do
    package_name 'pam'
    action :install
  end

  replace_or_add 'Restrict Core Dumps' do
    path '/etc/security/limits.conf'
    pattern '^\A\*\shard\score\s0'
    line '* hard core 0'
  end

end

# End xccdf_org.cisecurity.benchmarks_rule_1.6.1_Restrict_Core_Dumps
