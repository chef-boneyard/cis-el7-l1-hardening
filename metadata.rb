name 'cis-el7-l1-hardening'
maintainer 'Chef Software, Inc.'
maintainer_email 'cookbooks@chef.io'
license 'Apache-2.0'
description 'Installs/Configures cis-el7-l1-hardening'
long_description 'Installs/Configures cis-el7-l1-hardening'
issues_url 'https://github.com/chef-cookbooks/cis-el7-l1-hardening/issues'
source_url 'https://github.com/chef-cookbooks/cis-el7-l1-hardening'
version '0.7.0'
chef_version '>= 12.1' if respond_to?(:chef_version)

supports 'redhat'
supports 'centos'
depends 'line', '~> 0.6.3'
