#
# Cookbook Name:: sa-hardening
# Recipe:: enable_sudo_no_tty
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

execute 'sed -i \'s/^Defaults    requiretty/# Defaults    requiretty/g\' /etc/sudoers'
