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

  # Start fix for xccdf_org.cisecurity.benchmarks_rule_6.3.4_Limit_Password_Reuse
  # Start fix for xccdf_org.cisecurity.benchmarks_rule_5.3.3_Ensure_password_reuse_is_limited
  file '/etc/pam.d/system-auth' do
    manage_symlink_source true
    mode '0644'
    owner 'root'
    group 'root'
    action :create
  end

  replace_or_add 'Limit Password Reused system-auth' do
    path '/etc/pam.d/system-auth'
    pattern 'auth        sufficient    pam_unix.so remember=.*'
    line 'auth        sufficient    pam_unix.so remember=5'
  end

  replace_or_add 'Limit Password Reused password-auth' do
    path '/etc/pam.d/password-auth'
    pattern 'auth        sufficient    pam_unix.so remember=.*'
    line 'auth        sufficient    pam_unix.so remember=5'
  end
  # End fix for xccdf_org.cisecurity.benchmarks_rule_5.3.3_Ensure_password_reuse_is_limited
  # End fix for xccdf_org.cisecurity.benchmarks_rule_6.3.4_Limit_Password_Reuse

  # Fix for xccdf_org.cisecurity.benchmarks_rule_5.3.2_Ensure_lockout_for_failed_password_attempts_is_configured
  replace_or_add 'Ensure lockout for failed password attempts is configured: p-a-required' do
    path '/etc/pam.d/password-auth'
    pattern 'auth        required      pam_faillock.so*'
    line 'auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900'
  end

  replace_or_add 'Ensure lockout for failed password attempts is configured: p-a-[default=die]' do
    path '/etc/pam.d/password-auth'
    pattern 'auth        [default=die]      pam_faillock.so*'
    line 'auth        [default=die]      pam_faillock.so authfail audit deny=5 unlock_time=900'
  end

  replace_or_add 'Ensure lockout for failed password attempts is configured: p-a-sufficent' do
    path '/etc/pam.d/password-auth'
    pattern 'auth        sufficient      pam_faillock.so*'
    line 'auth        sufficient      pam_faillock.so authsucc audit deny=5 unlock_time=900'
  end

  replace_or_add 'Ensure lockout for failed password attempts is configured: s-a-required' do
    path '/etc/pam.d/system-auth'
    pattern 'auth        required      pam_faillock.so*'
    line 'auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900'
  end

  replace_or_add 'Ensure lockout for failed password attempts is configured: s-a-[default=die]' do
    path '/etc/pam.d/system-auth'
    pattern 'auth        [default=die]      pam_faillock.so*'
    line 'auth        [default=die]      pam_faillock.so authfail audit deny=5 unlock_time=900'
  end

  replace_or_add 'Ensure lockout for failed password attempts is configured: s-a-sufficent' do
    path '/etc/pam.d/system-auth'
    pattern 'auth        sufficient      pam_faillock.so*'
    line 'auth        sufficient      pam_faillock.so authsucc audit deny=5 unlock_time=900'
  end
end
