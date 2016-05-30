# cis-el7-l1-hardening

This cookbook provides a sample set of recipes for in order demonstrate on how you can make a RHEL 7 more CIS L1 compliant. It should be used in conjunction with [Chef Compliance](https://www.chef.io/compliance/)'s CIS L1 profile.

*Note*: This cookbook does not make your system pass *all* CIS L1 tests; just a portion in order to demonstrate how you can harden your RHEL 7 instances.

## Coding guidelines

Use Chef resources (versus the 'execute' resource) whenever possible.  The line cookbook is included for making line by line substitutions in config files.  See the `enable_sudo_no_tty.rb` for
a usage example.
