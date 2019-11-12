
import subprocess
import boto3
import time

from .resourcemodule import SecurityGroup
from .seekraux import *

############################
# Identify Security Groups #
############################

def output_sec_group(profile, region):
    print(bcolors.WARNING + '''           ,,. ,,.
      .******. ,******
    .********. .********.
   **********. .**********
  ,**********. .***********
 .******/****. .****/******.
 *#####( *(/*. .*((, (#####,
 .,,,,,.  ,**. ,**.  ,,,,,,.
 ,***********. .***********
  (**********. .**********/
   (*********. .*********(
    /(******/, */*****/(,
      ,(#(/**. .**/(#(
          ,//* ///.
          ''' + bcolors.ENDC)
    print('Checking Security Groups for {}\n'.format(profile))

    session = boto3.Session(profile_name='{}'.format(profile), region_name=region)
    ec2_client = session.client('ec2')

    security_group_list = []

    for region in ec2_client.describe_regions()['Regions']:
        print('Checking region {}...'.format(region['RegionName']))
        ec2_region_client = session.client('ec2', region_name='{}'.format(region['RegionName']))

        for security_group in ec2_region_client.describe_security_groups()['SecurityGroups']:

            current_group = SecurityGroup(security_group, region['RegionName'])
            if current_group.publicIngress == True:
                security_group_list.append(current_group)

    print('Finished building list of security groups.\n')
    return security_group_list
