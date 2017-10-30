# cis-el7-l1-hardening

This cookbook provides a sample set of recipes for in order demonstrate on how you can make a RHEL 7 more CIS L1 compliant. It should be used in conjunction with [Chef Compliance](https://www.chef.io/compliance/)'s CIS L1 profile.

*Note*: This cookbook does not make your system pass *all* CIS L1 tests; just a portion in order to demonstrate how you can harden your RHEL 7 instances.

## Requirements

### Platforms

- RHEL/CentOS

### Chef

- Chef 12.1+

### Cookbooks

- line

## Coding guidelines

Use Chef resources (versus the 'execute' resource) whenever possible.  The line cookbook is included for making line by line substitutions in config files.  See the `enable_sudo_no_tty.rb` for
a usage example.


## Maintainers

This cookbook is maintained by Chef's Community Cookbook Engineering team. Our goal is to improve cookbook quality and to aid the community in contributing to cookbooks. To learn more about our team, process, and design goals see our [team documentation](https://github.com/chef-cookbooks/community_cookbook_documentation/blob/master/COOKBOOK_TEAM.MD). To learn more about contributing to cookbooks like this see our [contributing documentation](https://github.com/chef-cookbooks/community_cookbook_documentation/blob/master/CONTRIBUTING.MD), or if you have general questions about this cookbook come chat with us in #cookbok-engineering on the [Chef Community Slack](http://community-slack.chef.io/)

## License

**Copyright:** 2017, Chef Software, Inc.

```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
