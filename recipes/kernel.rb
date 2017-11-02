# -*- coding: utf-8 -*-
#
# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: kernel
#
# Copyright (c) 2017 Chef Software

# 1.1.1.1_Ensure_mounting_of_cramfs_filesystems_is_disabled
# 1.1.1.2_Ensure_mounting_of_freevxfs_filesystems_is_disabled: Ensure mounting of freevxfs filesystems is disabled
# 1.1.1.3_Ensure_mounting_of_jffs2_filesystems_is_disabled: Ensure mounting of jffs2 filesystems is disabled
# 1.1.1.4_Ensure_mounting_of_hfs_filesystems_is_disabled: Ensure mounting of hfs filesystems is disabled
# 1.1.1.5_Ensure_mounting_of_hfsplus_filesystems_is_disabled: Ensure mounting of hfsplus filesystems is disabled
# 1.1.1.6_Ensure_mounting_of_squashfs_filesystems_is_disabled: Ensure mounting of squashfs filesystems is disabled
# 1.1.1.7_Ensure_mounting_of_udf_filesystems_is_disabled: Ensure mounting of udf filesystems is disabled
# 1.1.1.8_Ensure_mounting_of_FAT_filesystems_is_disabled: Ensure mounting of FAT filesystems is disabled
# 3.5.1_Ensure_DCCP_is_disabled: Ensure DCCP is disabled
# 3.5.2_Ensure_SCTP_is_disabled: Ensure SCTP is disabled
# 3.5.3_Ensure_RDS_is_disabled: Ensure RDS is disabled
# 3.5.4_Ensure_TIPC_is_disabled: Ensure TIPC is disabled

modules = %w{ cramfs crc-itu-t dccp fat freevxfs hfs hfsplus jffs2 rds sctp squashfs tipc udf vfat }

modules.each do |mod|
  execute "rmmod #{mod}" do
    only_if "lsmod | grep #{mod}"
  end

  file "blacklist #{mod}" do
    path "/etc/modprobe.d/#{mod}.conf"
    content "install #{mod} /bin/true"
  end
end
