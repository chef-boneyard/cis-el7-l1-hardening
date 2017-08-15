# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: login_banners
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

case node['platform_family']
when 'rhel'

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_8.2_Remove_OS_Information_from_Login_Warning_Banners
  ['/etc/motd', '/etc/issue', '/etc/issue.net'].each do |loginfile|
    file loginfile do
      mode 0644
      owner 'root'
      group 'root'
      action :create
    end

    execute "Delete OS Version from #{loginfile}" do
      command "/usr/bin/sed -i 's/\\\\v/REDACTED_OSVER/g' #{loginfile}"
      not_if "/usr/bin/grep REDACTED_OSVER #{loginfile}"
      only_if "/usr/bin/grep '\\\\v' #{loginfile}"
    end

    execute "Delete Kernel Version from #{loginfile}" do
      command "/usr/bin/sed -i 's:\\\\r:REDACTED_KERNELVER:g' #{loginfile}"
      not_if "/usr/bin/grep REDACTED_KERNELVER #{loginfile}"
      only_if "/usr/bin/grep '\\\\r' #{loginfile}"
    end

    execute "Delete Machine Architecture from #{loginfile}" do
      command "/usr/bin/sed -i 's/\\\\m/REDACTED_ARCH/g' #{loginfile}"
      not_if "/usr/bin/grep REDACTED_ARCH #{loginfile}"
      only_if "/usr/bin/grep '\\\\m' #{loginfile}"
    end

    execute "Delete OS used from #{loginfile}" do
      command "/usr/bin/sed -i 's/\\\\s/REDACTED_OS/g' #{loginfile}"
      not_if "/usr/bin/grep REDACTED_OS #{loginfile}"
      only_if "/usr/bin/grep '\\\\s' #{loginfile}"
    end
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_8.2_Remove_OS_Information_from_Login_Warning_Banners
end
