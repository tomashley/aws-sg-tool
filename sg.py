#!/usr/bin/env python

"""
inspired by https://gist.github.com/steder/1498451

This python script contains an SecGroup class to idempotently create
security groups in AWS from a json rules file and cli options,
or a config file
"""

from boto.ec2 import connect_to_region
import json
import re
import config


class SecGroup:

    def __init__(self):
        # TODO load ec2 credentials from config file
        creds = config.get_ec2_conf()
        self.conn = None
        self.access_key = creds['AWS_ACCESS_KEY_ID']
        self.secret_key = creds['AWS_SECRET_ACCESS_KEY']
        self.region = 'us-east-1'
        self.account_id = creds['ACCOUNT_ID']

        # create a connection to aws to pass around
        self.conn = connect_to_region(self.region,
                                      aws_access_key_id=self.access_key,
                                      aws_secret_access_key=self.secret_key)

        self.SecurityGroupRule = config.SecurityGroupRule

    def get_or_create_security_group(self,
                                     group_name,
                                     description=""):
        """
        Creates a new security group of retrieves the security group object
        if it already exists
        """

        groups = [g for g in self.conn.get_all_security_groups()
                    if g.name == group_name]
        group = groups[0] if groups else None
        if not group:
            # create the group
            print "Creating group %s" % (group_name)
            group = self.conn.create_security_group(group_name, description)
        return group

    def modify_sg(self, group, rule, authorize=False, revoke=False):
        """
        """
        # see if this is authorizing a local or foreign sg for access
        foreign = False
        if rule.src_group_name:
            if re.match('\d.*/sg-.*', rule.src_group_name):
                # foreign rule! accept it to go though
                foreign = True
                foreign_owner_id = rule.src_group_name.split('/')[0]
                foreign_group_id = rule.src_group_name.split('/')[1]

        if not foreign:
            # return the group ID from the name (ensures it is valid)
            src_group = None
            if rule.src_group_name:
                src_group = self.conn.get_all_security_groups([rule.src_group_name])[0]

        if authorize and not revoke:
            print "Authorizing missing rule %s" % (rule,)

            if foreign:
                # need to go through the conn resource to change src_owner_id
                self.conn.authorize_security_group(group_name=group.name,
                                    # or group_id='',
                                    src_security_group_group_id=foreign_group_id,
                                    src_security_group_owner_id=foreign_owner_id,
                                    ip_protocol=rule.ip_protocol,
                                    from_port=rule.from_port,
                                    to_port=rule.to_port,
                                    cidr_ip=rule.cidr_ip)
            else:
                # local sg, use the group ref passed in
                group.authorize(ip_protocol=rule.ip_protocol,
                                from_port=rule.from_port,
                                to_port=rule.to_port,
                                cidr_ip=rule.cidr_ip,
                                src_group=src_group)

        elif not authorize and revoke:
            print "Revoking unexpected rule %s" % (rule,)
            group.revoke(ip_protocol=rule.ip_protocol,
                         from_port=rule.from_port,
                         to_port=rule.to_port,
                         cidr_ip=rule.cidr_ip,
                         src_group=src_group)

    def authorize(self, group, rule):
        """ add a rule to a security group """
        return self.modify_sg(group, rule, authorize=True)

    def revoke(self, group, rule):
        """ remove a rule from a security group """
        # return self.modify_sg(group, rule, revoke=True)
        # turn this off for now
        pass

    def update_security_group(self, group, expected_rules):
        """
        """
        print "updating group %s..." % (group.name)
        import pprint
        print "Expected Rules:"
        pprint.pprint(expected_rules)

        current_rules = []
        for rule in group.rules:
            if not rule.grants[0].cidr_ip:
                # this is rule to permit in another security group
                # we need the owner id here in case it is a foreign rule
                if rule.grants[0].owner_id != self.account_id:
                    # foreign SG
                    grant_name = "%s/%s" % (rule.grants[0].owner_id,
                                            rule.grants[0].group_id)
                else:
                    grant_name = rule.grants[0].name
                current_rule = \
                    self.SecurityGroupRule(rule.ip_protocol,
                                           rule.from_port,
                                           rule.to_port,
                                           "0.0.0.0/0",
                                           grant_name)
            else:
                # this is a rule to allow in an ip or network
                current_rule = \
                    self.SecurityGroupRule(rule.ip_protocol,
                                           rule.from_port,
                                           rule.to_port,
                                           rule.grants[0].cidr_ip,
                                           None)

            if current_rule not in expected_rules:
                self.revoke(group, current_rule)
            else:
                current_rules.append(current_rule)

        print "Current Rules:"
        pprint.pprint(current_rules)

        for rule in expected_rules:
            if rule not in current_rules:
                # print "passing in rule"
                # pprint.pprint(rule)
                self.authorize(group, rule)

    def list_sgs_and_rules(self, group_list=""):
        """ List all security groups based on a filter list passed """
        print "Security groups in list '%s'" % (", ".join(group_list))
        groups = self.conn.get_all_security_groups(groupnames=group_list)
        current_rules = {}
        for group in groups:
            current_rules[group.name] = []
            for rule in group.rules:
                if not rule.grants[0].cidr_ip:
                    # this is rule to permit in another security group
                    # we need the owner id here in case it is a foreign rule
                    if rule.grants[0].owner_id != self.account_id:
                        # foreign SG
                        grant_name = "%s/%s" % (rule.grants[0].owner_id,
                                                rule.grants[0].group_id)
                    else:
                        grant_name = rule.grants[0].name
                    current_rule = \
                        self.SecurityGroupRule(rule.ip_protocol,
                                               rule.from_port,
                                               rule.to_port,
                                               "0.0.0.0/0",
                                               grant_name)
                else:
                    # this is a rule to allow in an ip or range of ips
                    current_rule = \
                        self.SecurityGroupRule(rule.ip_protocol,
                                               rule.from_port,
                                               rule.to_port,
                                               rule.grants[0].cidr_ip,
                                               None)

                current_rules[group.name].append(current_rule)
        print json.dumps(current_rules)




# END SecGroup class




# load security group info from file
# TODO: I want this to be configurable as a cli switch
# open file

# do some work here:
# create the security groups

mysg = SecGroup()

for sg in config.SECURITY_GROUPS:
    # print sg[0]
    # print sg[1]
    # print sg[2]
    group = mysg.get_or_create_security_group(sg[0], sg[1])
    mysg.update_security_group(group, sg[2])
