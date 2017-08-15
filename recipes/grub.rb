# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: grub
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


# Start fix for xccdf_org.cisecurity.benchmarks_rule_1.5.2_Set_Permissions_on_bootgrub2grub.cfg
package 'Install grub2' do
  package_name 'grub2'
  action :install
end

file '/boot/grub2/grub.cfg' do
  mode '0600'
  owner 'root'
  group 'root'
  action :create
end
# End fix for xccdf_org.cisecurity.benchmarks_rule_1.5.2_Set_Permissions_on_bootgrub2grub.cfg
