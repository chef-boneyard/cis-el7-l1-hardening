#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: enable_sudo_no_tty
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

# Ensure sudo is installed
package 'Install sudo' do
  package_name 'sudo'
  action :install
end

file '/etc/sudoers' do
  mode 0440
  owner 'root'
  group 'root'
  action :create
end

delete_lines 'remove hash-comments from /some/file' do
  path '/etc/sudoers'
  pattern '^.*requiretty'
end
