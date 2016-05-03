# sa-hardening

This cookbook provides recipes for ensuring that a RHEL-7 system is compliant with the Lightweight CIS-L1 Chef Compliance profile.

## Coding guidelines

Use Chef resources wherever possible.  The line cookbook is included for making line by line substitutions in config files.  See the `enable_sudo_no_tty.rb` for
a usage example.

## Testing the cookbook

As the results of the cookbook need to be verified by running a Compliance scan against them it is recommended to use an EC2 test-kitchen instance.  The default .kitchen.yml file creates one using the emea-sa-shared key.

### Adding your test-kitchen instance to Compliance automatically

The provided Rakefile has two tasks to allow you to automatically add your test-kitchen instance into Compliance:

`rake setup_compliance_creds`

This asks for your Compliance Server username and your Compliance Refresh token as input and creates a `.compliance-creds` file in the root of the cookbook.  You can obtain your refresh token from the Compliance UI when logged in by clicking the user icon in the top right of the screen and clicking **about**

Note that the refresh token is long lived so you don't need to regenerate your compliance-creds unless `.compliance-creds` gets deleted

`rake add_compliance_node`

Automatically adds the test-kitchen node to Compliance with the correct user credentials.

Note that this assumes you already have a private key setup in Compliance called *emea-sa-shared*
