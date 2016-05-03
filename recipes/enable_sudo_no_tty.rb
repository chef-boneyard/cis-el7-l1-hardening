#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: enable_sudo_no_tty
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

#execute 'sed -i \'s/^Defaults    requiretty/# Defaults    requiretty/g\' /etc/sudoers'

delete_lines 'remove hash-comments from /some/file' do
  path '/etc/sudoers'
  pattern '^.*requiretty'
end
