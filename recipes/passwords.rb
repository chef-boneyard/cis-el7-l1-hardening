case node["platform_family"]
when 'rhel'

  # xccdf_org.cisecurity.benchmarks_rule_6.3.2_Set_Password_Creation_Requirement_Parameters_Using_pam_pwquality
  replace_or_add 'Set Password mimimum length' do
    path '/etc/security/pwquality.conf'
    pattern '# minlen'
    line 'minlen = 14'
  end

  replace_or_add 'Set password dcredit' do
    path '/etc/security/pwquality.conf'
    pattern '# dcredit'
    line 'dcredit = -1'
  end

  replace_or_add 'Set password ocredit' do
    path '/etc/security/pwquality.conf'
    pattern '# ocredit'
    line 'ocredit = -1'
  end
  replace_or_add 'Set password lcredit' do
    path '/etc/security/pwquality.conf'
    pattern '# lcredit'
    line 'lcredit = -1'
  end
  replace_or_add 'Set password ucredit' do
    path '/etc/security/pwquality.conf'
    pattern '# ucredit'
    line 'ucredit = -1'
  end

  # xccdf_org.cisecurity.benchmarks_rule_6.3.2_Set_Password_Creation_Requirement_Parameters_Using_pam_pwquality
end
