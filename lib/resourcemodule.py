#!/usr/bin/env python3
import subprocess

from .seekraux import *

########################
# AWS Resource Classes #
########################

#----------------#
# Security Groups
#----------------#

class SecurityGroup:
    '''Security Group Class

    This class contains a constructor, and two output methods. The constructor
    takes a json blob and creates an object with several security relevant
    properties. The output functions parse the data in each object to provide
    relevant information about the object from a security point of view.
    '''

    def __init__(self, security_group_blob, region):
        self.region = region
        self.groupName = security_group_blob['GroupName']
        self.groupId = security_group_blob['GroupId']
        self.publicIngress = False
        self.publicEgress = False
        self.ingressList = []  # List of rules. Example: rule = [[22,443,666], [0.0.0.0, 127.0.0.1]]
        self.egressList = []
        self.warning = False
        self.public_map = ''
        for ip_permission in security_group_blob['IpPermissions']:
            ports = []
            ips = []
            if '0.0.0.0/0' in str(ip_permission) and (ip_permission.get('FromPort') != None and ip_permission.get('ToPort') != None):
                self.publicIngress = True
                ips.append('0.0.0.0/0')
                for i in range(ip_permission.get('FromPort'), ip_permission.get('ToPort') + 1):
                    ports.append(i)
                rule = [ports, ips]
                self.ingressList.append(rule)

    def output_summary(self):
        print('Results for [{}]'.format(self.groupName))
        print('[' + bcolors.UNICODE_PASS_BLUE \
        + '] Region: {}'.format(self.region))
        if(self.publicIngress == True):
            print('[' + bcolors.UNICODE_WARNING_2 + '] This security group has public access allowed on one or more ports')

    def output_details(self):
        if self.public_map != '':
            print('[' + bcolors.UNICODE_WARNING_2 + '] A public route was found to this security group via the following group relationship: {}'.format(self.public_map))
        if(self.publicIngress == True):
            for rule in self.ingressList:
                if len(rule[0]) == 1:
                    temprule = rule[0][0]
                elif len(rule[0]) > 1:
                    temprule = '{}-{}'.format(rule[0][0], rule[0][-1])
                if '22' and 22 not in rule[0]:
                        print('[' + bcolors.UNICODE_WARNING_2 + '] ........ Public access allowed to port {}'.format(temprule))
                elif '22' or 22 in rule[0]:
                        print('[' + bcolors.UNICODE_FAIL + '] ........ Public access allowed to port 22, remediation required')
                else:
                    print('    ........ Destination port undefined.')
        print('')

#--------------#
# EC2 Instances
#--------------#

class Ec2Instance:
    '''EC2 Instance Class

    This class contains a constructor, and two output methods, just like the
    Security Group Class. Additionally, the EC2 instance class contains the
    Shodan check method, so that objects may update themselves to check for
    hits on shodan.io.
    '''

    def __init__(self, ec2_blob, region):
        self.region = region
        self.instanceName = 'Unnamed Instance'
        if ec2_blob.get('Tags'):
            for tag in ec2_blob['Tags']:
                if 'Name' in tag['Key']:
                    self.instanceName = tag['Value']

        self.instanceId = ec2_blob['InstanceId']
        self.publicIp = None
        if ec2_blob.get('PublicIpAddress'):
            self.publicIp = ec2_blob['PublicIpAddress']

        self.privateIp = ec2_blob['PrivateIpAddress']
        self.securityGroups = ec2_blob['SecurityGroups']
        self.publicSecurityGroups = []
        self.shodanAccess = False
        self.publicSecurityGroup = False
        self.warning = False

    def shodan_check(self):
        shodan_check = subprocess.Popen(['curl',
                                         'https://www.shodan.io/host/{}'.format(self.publicIp)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        shodan_stream = shodan_check.communicate()[0]
        if b'404 Not Found' in shodan_stream:
            return
        else:
            self.shodanAccess = True
        return

    def output_summary(self):
        print('Results for [{}]'.format(self.instanceName))
        if self.warning == True:
            print('[' + bcolors.UNICODE_FAIL + '] Exposure detected.')
        elif self.warning == False:
            print('[' + bcolors.UNICODE_PASS_GREEN \
            + '] No exposure detected.')
        print('[' + bcolors.UNICODE_PASS_BLUE \
        + '] Region: {}'.format(self.region))
        print('[' + bcolors.UNICODE_PASS_BLUE \
        + '] {} has the public ip {}'.format(self.instanceId, self.publicIp))

    def output_details(self):

        if len(self.publicSecurityGroups) > 0:
            for security_group in self.publicSecurityGroups:
                print('[' + bcolors.UNICODE_FAIL \
                    + '] The instance has the public security group {} attached directly'.format(security_group.groupName))
                security_group.output_details()


        if self.shodanAccess == False:
            print('[' + bcolors.UNICODE_PASS_BLUE \
            + '] ........ No hits on Shodan')
        elif self.shodanAccess == True:
            print('[' + bcolors.UNICODE_WARNING_2 \
            + '] ........ Hit on ' + bcolors.UNDERLINE \
            + 'https://www.shodan.io/host/{}'.format(self.publicIp) + bcolors.ENDC)

        if not self.publicSecurityGroup and self.shodanAccess:
            print('[' + bcolors.UNICODE_WARNING_2 \
            + '] This instance has no directly attached public security group,'\
            + ' but can still be reached from the anywhere on the internet')
        elif not self.publicSecurityGroup and not self.shodanAccess:
            print('[' + bcolors.UNICODE_PASS_GREEN \
            + '] This instance is properly situated behind the virtual firewall')
        print('')
