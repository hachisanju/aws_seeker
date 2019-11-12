import boto3
from .seekraux import *


def dynamodb_check(session, region):
    print('Checking region {}...'.format(region['RegionName']))
    dynamo_client = session.client('dynamodb', region_name='{}'.format(region['RegionName']))

    tables = dynamo_client.list_tables()['TableNames']

    for table in tables:
        tabledata = dynamo_client.describe_table(TableName=table)['Table']
        print('Evaluating controls for {}'.format(table))
        print('Table has the ARN {}'.format(tabledata['TableArn']))
        if 'SSEDescription' in str(tabledata):
            if tabledata['SSEDescription']['Status'] == 'ENABLED':
                print('[' + bcolors.UNICODE_PASS_GREEN + '] ........ Storage for DB is encrypted')
            else:
                print('[' + bcolors.UNICODE_WARNING_2 + '] ........ Storage for DB is not encrypted')
        else:
            print('[' + bcolors.UNICODE_WARNING_2 + '] ........ Storage for DB is not encrypted and DB must be rebuilt to enable encryption')


def rds_check(session, region, secglist):
    print('Checking region {}...'.format(region['RegionName']))
    rds_client = session.client('rds', region_name='{}'.format(region['RegionName']))

    for database in rds_client.describe_db_instances()['DBInstances']:
        print('Evaluating controls for {}'.format(database['DBInstanceIdentifier']))
        endpoint = database['Endpoint']
        print('[' + bcolors.UNICODE_PASS_BLUE + '] ........ DB is accessed via {}:{}'.format(endpoint['Address'], endpoint['Port']))
        if database['StorageEncrypted'] == False:
            print('[' + bcolors.UNICODE_WARNING_2 + '] ........ Storage for DB is not encrypted')
        elif database['StorageEncrypted'] == True:
            print('[' + bcolors.UNICODE_PASS_GREEN + '] ........ Storage for DB is encrypted')
        if database['PubliclyAccessible'] == False:
            print('[' + bcolors.UNICODE_PASS_GREEN + '] ........ DB is not externally accessible')
        elif database['PubliclyAccessible'] == True:
            print('[' + bcolors.UNICODE_WARNING_2 + '] ........ DB is externally accessible')
        security_groups = database['VpcSecurityGroups']
        for database_group in security_groups:
            for group in secglist:
                if group.groupId == database_group['VpcSecurityGroupId']:
                    print('[' + bcolors.UNICODE_FAIL + '] ............ RDS instance has public security group {} attached'.format(group['GroupName']))

######################################################################
                                            #Identify Security Groups#
######################################################################
def output_rds(profile, secglist, region):
    print(bcolors.OKBLUE + '''
        ,#%(######//,
     /#%%%%(######/(((//
   ,%%#%%%%%%%%%%%%#((/(#*
   (%%%%%%%#######(#%%%%#(
   ,%%#%%%%(######/(((/(#,
   (%%%%%%%#######/(((((#(
   ,#%%%%%%%%%%%%%%%%%%##,
   (%%#%%%%(######/(((/(#(
   (%%%%%%%(######/(((##%(
   (%%%%%%%%%%%%%%%%%#((#(
     %%%%%%(######/(((/(.
       /#%%(######/(/*
           .......
          ''' + bcolors.ENDC)
    print('Checking RDS instances for {}\n'.format(profile))
    session = boto3.Session(profile_name='{}'.format(profile), region_name=region)
    region_client = session.client('ec2')
    regions = region_client.describe_regions()['Regions']
    for region in regions:
        rds_check(session, region, secglist)

    print('Checking DynamoDB tables for {}\n'.format(profile))
    for region in regions:
        dynamodb_check(session, region)

    return
