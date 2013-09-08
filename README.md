== aws-sg-tool

=== Overview:
A tool to bring AWS Security Groups in-line with that declared in the config file.
This will delete unknown rules and ensure only the rules you have in version control
are in Amazon.
Config management for AWS SG rules, if you will.

=== Usage
* Add rules to config.py
* Add security group names, description and a link back to the rules after the rules tuples
    - Add them in the order they need to be created so addtions don't fail

=== TODO
LOTS
* Pull back existing rules from AWS and populate config file
* add cli options for security group matching
* add cli options for config file
* change config file format (probably to json yaml)
* add cli passing in new rules file format

** DISCLAIMER
This is not yet being used in anger and I cannot be held responsible if you get locked
out of your ec2 instances

