case node['platform_family']
when 'rhel'

  # Ensure package is installed
  package 'Install libpwquality' do
    package_name 'libpwquality'
    action :install
  end

  # Ensure configuration file is present
  file '/etc/security/pwquality.conf' do
    mode 0644
    owner 'root'
    group 'root'
    action :create
  end

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

  execute 'Set Password Expiring Warning Days in /etc/shadow' do
    command "/usr/bin/sed -i 's/::\\([^:]*:[^:]*:\\)$/:7:\\1/g' /etc/shadow"
    only_if "/usr/bin/grep '::\\([^:]*:[^:]*:\\)$' /etc/shadow"
  end

  replace_or_add 'Set Password Expiration Days in login.defs' do
    path '/etc/login.defs'
    pattern '^PASS_MAX_DAYS\s+(9[1-9]|[1-9][0-9]{2,})?'
    line 'PASS_MAX_DAYS	90'
  end

  execute 'Set Password Expiration Days in /etc/shadow' do
    command "/usr/bin/sed -i 's/:\\(9[1-9]\\|[1-9][0-9]\\{2,\\}\\)\\?:\\([^:]*:[^:]*:[^:]*:$\\)/:90:\\2/g' /etc/shadow"
    only_if "/usr/bin/grep ':\\(9[1-9]\\|[1-9][0-9]\\{2,\\}\\)\\?:[^:]*:[^:]*:[^:]*:$' /etc/shadow"
  end

  replace_or_add 'Set Password Change Minimum Number of Days in login.defs' do
    path '/etc/login.defs'
    pattern 'PASS_MIN_DAYS\s+[0-6]?$'
    line 'PASS_MIN_DAYS	7'
  end

  execute 'Set Password Change Minimum Number of Days in /etc/shadow' do
    command "/usr/bin/sed -i 's/:[0-6]\\?:\\([^:]*:[^:]*:[^:]*:[^:]*:$\\)/:7:\\1/g' /etc/shadow"
    only_if "/usr/bin/grep ':[0-6]\\?:[^:]*:[^:]*:[^:]*:[^:]*:$' /etc/shadow"
  end
  # xccdf_org.cisecurity.benchmarks_rule_6.3.2_Set_Password_Creation_Requirement_Parameters_Using_pam_pwquality
end
