describe file("/etc/security/limits.conf") do
   its(:content) { should match /^\s*\*\shard\score\s0(\s+#.*)?$/ }
 end
