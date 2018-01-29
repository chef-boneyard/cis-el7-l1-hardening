# -*- coding: utf-8 -*-
#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: partitions
#
# Copyright (c) 2017 Chef Software

# https://www.cyberciti.biz/faq/linux-add-nodev-nosuid-noexec-options-to-temporary-storage-partitions/
# These do not persist yet

# 1.1.3_Ensure_nodev_option_set_on_tmp_partition: Ensure nodev option set on /tmp partition
# 1.1.4_Ensure_nosuid_option_set_on_tmp_partition: Ensure nosuid option set on /tmp partition
# 1.1.5_Ensure_noexec_option_set_on_tmp_partition: Ensure noexec option set on /tmp partition
execute 'mount -o remount,nosuid,nodev,noexec /tmp' do
  only_if 'findmnt /tmp'
  not_if 'findmnt /tmp | grep nosuid,nodev,noexec'
end

# 1.1.8_Ensure_nodev_option_set_on_vartmp_partition: Ensure nodev option set on /var/tmp partition
# 1.1.9_Ensure_nosuid_option_set_on_vartmp_partition: Ensure nosuid option set on /var/tmp partition
# 1.1.10_Ensure_noexec_option_set_on_vartmp_partition: Ensure noexec option set on /var/tmp partition
execute 'mount -o remount,nosuid,nodev,noexec /var/tmp' do
  only_if 'findmnt /var/tmp'
  not_if 'findmnt /var/tmp | grep nosuid,nodev,noexec'
end

# 1.1.14_Ensure_nodev_option_set_on_home_partition: Ensure nodev option set on /home partition
execute 'mount -o remount,nodev /home' do
  only_if 'findmnt /home'
  not_if 'findmnt /home | grep nodev'
end

# 1.1.15_Ensure_nodev_option_set_on_devshm_partition: Ensure nodev option set on /dev/shm partition
# 1.1.16_Ensure_nosuid_option_set_on_devshm_partition: Ensure nosuid option set on /dev/shm partition
# 1.1.17_Ensure_noexec_option_set_on_devshm_partition: Ensure noexec option set on /dev/shm partition
execute 'mount -o remount,nosuid,nodev,noexec /dev/shm' do
  only_if 'findmnt /dev/shm'
  not_if 'findmnt /dev/shm | grep nosuid,nodev,noexec'
end
