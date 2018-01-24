# Cookbook Name:: cis-el7-l1-hardening
# Recipe:: firewalld
#

# Fix for "xccdf_org.cisecurity.benchmarks_rule_4.7_Enable_firewalld"
package 'firewalld'

service 'firewalld' do
  supports :status => true
  action [:enable, :start]
end
# End fix for "xccdf_org.cisecurity.benchmarks_rule_4.7_Enable_firewalld"
