# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: avahi
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
    package 'Install Avahi Libs' do
      package_name 'avahi-libs'
      action :install
    end

    package 'Install Avahi Autoipd' do
      package_name 'avahi-autoipd'
      action :install
    end

    package 'Install Avahi' do
      package_name 'avahi'
      action :install
    end

    service 'avahi-daemon.socket' do
      provider Chef::Provider::Service::Systemd
      action [:disable, :stop]
    end

    service 'avahi-daemon.service' do
      provider Chef::Provider::Service::Systemd
      action [:disable, :stop]
    end

  end
end
