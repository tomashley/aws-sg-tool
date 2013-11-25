aws-sg-tool
===

Overview:
---
A tool to bring AWS Security Groups in-line with that declared in the config file.
This will delete unknown rules and ensure only the rules you have in version control
are in Amazon.
Config management for AWS SG rules, if you will.

Usage
---
* Add rules to a json rules file as per example_rules.json
* Rules can have a default section that are applied to all security groups subsequently
* Add security group names and a link back to the rules after the rules tuples

TODO
---
LOTS
* Pull back existing rules from AWS and populate config file
* add cli options for security group matching
* add cli options for config file
* add cli passing in new rules file format

** DISCLAIMER
This is not yet being used in anger and I cannot be held responsible if you get locked
out of your ec2 instances

