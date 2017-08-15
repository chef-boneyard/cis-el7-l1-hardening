#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: default
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
  if node['platform_version'].to_f >= 7.0

    # Remiation recipes includes (alphabetical)
    include_recipe 'cis-el7-l1-hardening::at_daemon'
    include_recipe 'cis-el7-l1-hardening::avahi'
    include_recipe 'cis-el7-l1-hardening::core_dumps'
    include_recipe 'cis-el7-l1-hardening::cron'
    include_recipe 'cis-el7-l1-hardening::firewalld'
    include_recipe 'cis-el7-l1-hardening::grub'
    include_recipe 'cis-el7-l1-hardening::init'
    include_recipe 'cis-el7-l1-hardening::login_banners'
    include_recipe 'cis-el7-l1-hardening::network-packet-remediation'
    include_recipe 'cis-el7-l1-hardening::ntp'
    include_recipe 'cis-el7-l1-hardening::rsyslog'
    include_recipe 'cis-el7-l1-hardening::ssh'
    include_recipe 'cis-el7-l1-hardening::user-mgmt'

    # This should be the last recipe thats run as it remediates
    # the shadow file to a CIS compliant standard and prior recipes may have
    # influence additions / removals to the shadow file.
    #
    include_recipe 'cis-el7-l1-hardening::passwords'

  end
end
