describe limits_conf do
        its('*') { should include ['hard','core','0'] }
end
