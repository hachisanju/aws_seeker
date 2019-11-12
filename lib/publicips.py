
import subprocess
import boto3

from .resourcemodule import Ec2Instance
from .seekraux import *

##############################################
# Identify Publicly Accessible EC2 Resources #
##############################################

def security_group_check(ec2_instance, sec_g_list):
    '''Function to compare public ips against
    publicly accessible security groups
    '''
    public = False
    if sec_g_list:
        for security_group in sec_g_list:
            if security_group.groupName and security_group.groupId in str(ec2_instance.securityGroups):
                ec2_instance.publicSecurityGroups.append(security_group)
                public = True
    return public

def region_check(session, region, public_instances, sec_g_list):
    '''Function to check instances by region
    '''
    public_instances = []

    print('Checking region {}...'.format(region['RegionName']))
    b3ses = session.client('ec2', region_name='{}'.format(region['RegionName']))
    instances = b3ses.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running',]}])

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            ec2_instance = Ec2Instance(instance, region['RegionName'])
            if ec2_instance.publicIp != None:

                ec2_instance.publicSecurityGroup = security_group_check(ec2_instance, sec_g_list)

                ec2_instance.shodan_check()

                if ec2_instance.publicSecurityGroup:
                    ec2_instance.warning = True
                public_instances.append(ec2_instance)

    return public_instances

def identify_public_ips(profile, sec_g_list, region):
    print('''\033[38;2;255;165;0m             *(*,
         */**##////*,
     .#//#(//##/////////,
   ///#//#(//##///////////*
   (//#//#(//##///////////*
   ///#//#(//##///////////*
   ///#//#(//##///////////*
   ///#//#(//##///////////*
   ///#//#(//##///////////*
   ///#//#(//##///////////*
   ///#//#(//##///////////*
   .,,#//#(//##//////////*
         #(//##//////*
            .##//,
                          \033[0;m''')

    print('Checking Public Instances for {}\n'.format(profile))
    session = boto3.Session(profile_name='{}'.format(profile), region_name=region)
    b3ses = session.client('ec2')
    public_instances = []
    for region in b3ses.describe_regions()['Regions']:
        public_instances += region_check(session, region, public_instances, sec_g_list)

    print('Finished building list of EC2 Instances.\n')
    return public_instances
