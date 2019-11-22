import boto3
from .seekraux import *
from ast import literal_eval

#CLIENT = boto3.client('s3')


def check_encryption(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_encryption(Bucket='{}'.format(bucket_name))
        print('[' + bcolors.UNICODE_PASS_GREEN \
        + '] Bucket uses server side encryption with the algorithm {}'.format(response.get('ServerSideEncryptionConfiguration').get('Rules')[0].get('ApplyServerSideEncryptionByDefault').get('SSEAlgorithm')))
    except Exception as e:
        if 'AccessDenied' in str(e):
            print('[' + bcolors.UNICODE_WARNING_2 + '] Access was denied.')
        elif 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
            print('[' + bcolors.UNICODE_WARNING_2 + '] Encryption is not enabled.')
        else:
            print(e)
    try:
        bucket_logging = s3_client.get_bucket_logging(Bucket='{}'.format(bucket_name))
        if 'LoggingEnabled' not in str(bucket_logging):
            print('[' + bcolors.UNICODE_WARNING_2 + '] Logging is not enabled.')
        else:
            print('[' + bcolors.UNICODE_PASS_GREEN \
            + '] Bucket logging is enabled with target {}'.format(bucket_logging.get('LoggingEnabled').get('TargetBucket')))
    except Exception as e:
        print(e)

    try:
        bucket_versioning = s3_client.get_bucket_versioning(Bucket='{}'.format(bucket_name))
        if 'Enabled' not in str(bucket_versioning):
            print('[' + bcolors.UNICODE_WARNING_2 + '] Versioning is not enabled.')
        else:
            print('[' + bcolors.UNICODE_PASS_GREEN \
            + '] Bucket versioning is enabled.')
    except Exception as e:
        print(e)

#######################################################################
                    #Identify S3 Buckets#
#######################################################################
def output_buckets(profile, region):
    print('''\033[1;31m            *#(/,
          #%%%((((/
   ..     #%%%((((/    ...
  #%((((((%%%%(((((#%%%%#(*
  #%(((((((#%%&&%%%%%%%%#(*
  #%(((((((((####%%%%%%%#(*
  #%((((((%%%%(((((%%%%%#(*
  #%((((((%%%%(((((%%%%%#(*
  #%((((((%%%%(((((%%%%%#(*
  #%((((((((((#%%%%%%%%%#(*
  #%((((((/**,,,*/(%%%%%#(*
  #%(((((*%%%%(((((/#%%%#(*
          #%%%((((/
          #%%%((((/
            .((*
\033[0m''')
    print('Checking S3 Buckets for {}\n'.format(profile))

    session = boto3.Session(profile_name='{}'.format(profile), region_name=region)
    s3_client = session.client('s3')

    all_buckets = s3_client.list_buckets().get('Buckets')

    violating_buckets = []
    violating_objects = []
    for bucket in all_buckets:
        print('Checking https://s3.amazonaws.com/' + bucket.get('Name'))
        check_encryption(s3_client, bucket.get('Name'))
        acl = get_violating_buckets(bucket, s3_client)
        policy = get_violating_bucket_policies(bucket, s3_client)

        print('    Sampling bucket ACLs...')
        if acl or policy:
            violating_buckets.append(bucket)
            try:
                for obj in s3_client.list_objects_v2(Bucket=bucket.get('Name'),MaxKeys=1).get('Contents'):
                    print('Check objects directly')
                    print(obj.get('Key'))
            except Exception as e:
                print('    ........ Could not find or access any objects')
        get_violating_objects(bucket, s3_client)

    #list_violating_acls(violating_objects)

    return

def get_violating_buckets(bucket, s3_client):

    violating = False

    bucket_name = bucket.get('Name')
    try:
        bucket_acl = s3_client.get_bucket_acl(Bucket=bucket_name)

        if bucket_acl.get('Grants'):
            for grant in bucket_acl.get('Grants'):
                bucket_grantee = grant.get('Grantee')
                if bucket_grantee.get('URI') and 'AllUsers' in bucket_grantee.get('URI'):
                    bucket_permission = grant.get('Permission')
                    if 'READ' in bucket_permission:
                        print('[' + bcolors.UNICODE_FAIL + '] ........ {} contains an ACL with READ access for ALL USERS.'.format(bucket_name))
                        violating = True
                    if 'WRITE' in bucket_permission:
                        print('[' + bcolors.UNICODE_FAIL + '] ........ {} contains an ACL with WRITE access for ALL USERS.'.format(bucket_name))
                        violating = True
                    if 'FULL_CONTROL' in bucket_permission:
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains an ACL with FULL CONTROL for ALL USERS.'.format(bucket_name))
                        violating = True

                if bucket_grantee.get('URI') and 'AuthenticatedUsers' in bucket_grantee.get('URI'):
                    bucket_permission = grant.get('Permission')
                    auth_users = True
                    print(bucket_permission)
                    if 'READ' in bucket_permission:
                        print('[' + bcolors.UNICODE_WARNING + '] ........ {} contains an ACL with READ access for users within the console.'.format(bucket_name))
                        violating = True
                    if 'WRITE' in bucket_permission:
                        print('[' + bcolors.UNICODE_WARNING + '] ........ {} contains an ACL with WRITE access for users within the console.'.format(bucket_name))
                        violating = True
                    if 'FULL_CONTROL' in bucket_permission:
                        print('[' + bcolors.UNICODE_WARNING_2 + '] ........ {} contains an ACL with FULL CONTROL access for users within the console.'.format(bucket_name))
                        violating = True
    except Exception as e:
        if 'AccessDenied' in str(e):
            print(bucket_name + ' could not be assessed due to an AccessDenied Error')

    return violating

def get_violating_objects(bucket, s3_client):
    bacl = False
    violating_objs = []
    list_of_objs = []
    #print("i am doing things")
    bucket_name = bucket.get('Name')
    try:
        bucket_obj_contents = s3_client.list_objects_v2(Bucket=bucket_name,MaxKeys=50).get('Contents')

        for obj in bucket_obj_contents:
            if obj.get('Key'):
                bucket_obj_dict = {
                    'BucketName': bucket_name,
                    'ObjectKey': obj.get('Key')
                }

                list_of_objs.append(bucket_obj_dict)
    except Exception as e:
        print('    ........ Could not find or access any objects')

    for obj in list_of_objs:
        obj_key = obj.get('ObjectKey')
        bucket_name = obj.get('BucketName')

        try:
            obj_acl = s3_client.get_object_acl(Bucket=bucket_name, Key=obj_key)
        except Exception as e:
            if 'AccessDenied' in str(e):
                print(bucket_name + ' could not be assessed due to an AccessDenied Error')
            continue

        if obj_acl.get('Grants'):
            for grant in obj_acl.get('Grants'):
                obj_grantee = grant.get('Grantee')
                if obj_grantee.get('URI') and 'AllUsers' in obj_grantee.get('URI'):
                    obj_permission = grant.get('Permission')
                    if 'READ' in obj_permission:
                        print('[' + bcolors.UNICODE_FAIL + '] ........ {} contains an ACL with READ access for ALL USERS.'.format(obj_key))
                    if 'WRITE' in obj_permission:
                        print('[' + bcolors.UNICODE_FAIL + '] ........ {} contains an ACL with WRITE access for ALL USERS.'.format(obj_key))
                    if 'FULL_CONTROL' in obj_permission:
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains an ACL with FULL CONTROL for ALL USERS.'.format(obj_key))

                if obj_grantee.get('URI') and 'AuthenticatedUsers' in obj_grantee.get('URI'):
                    obj_permission = grant.get('Permission')
                    if 'READ' in obj_permission:
                        print('[' + bcolors.UNICODE_FAIL + '] ........ {} contains an ACL with READ access for users within the console.'.format(obj_key))
                    if 'WRITE' in obj_permission:
                        print('[' + bcolors.UNICODE_FAIL + '] ........ {} contains an ACL with WRITE access for users within the console.'.format(obj_key))
                    if 'FULL_CONTROL' in obj_permission:
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains an ACL with FULL CONTROL for users within the console.'.format(obj_key))


    return violating_objs

def get_violating_bucket_policies(bucket, s3_client):
    list_of_policies = []
    clean = True
    bucket_name = bucket.get('Name')
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
    except Exception as e:
        if 'The bucket policy does not exist' in str(e):
            print('[' + bcolors.UNICODE_PASS_GREEN + '] Bucket does not contain a bucket policy.')
        return

    pol_dict = policy.get('Policy', {})
    pol_statements = literal_eval(pol_dict).get('Statement')

    for statement in pol_statements:
        if 'IpAddress' in str(statement):
            print('Access restricted to {}'.format(statement.get('Condition').get('IpAddress').get('aws:SourceIp')))
        if isinstance(statement.get('Principal'), list):
            if any('*' in  p for p in statement.get('Principal')) and 'Allow' in statement.get('Effect'):
                bpolicy = True

                if isinstance(statement.get('Action'), list):

                    if any('GetObject' in a for a in statement.get('Action')):
                        clean = False
                        print('[' + bcolors.UNICODE_WARNING_2 + '] ........ {} contains a Bucket Policy with READ access for ALL USERS.'.format(bucket_name))
                    if any('PutObject' in a for a in statement.get('Action')):
                        clean = False
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains a Bucket Policy with WRITE access for ALL USERS.'.format(bucket_name))
                    if any('*' in a for a in statement.get('Action')):
                        clean = False
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains a Bucket Policy with FULL CONTROL for ALL USERS.'.format(bucket_name))
                else:
                    if 'GetObject' in statement.get('Action'):
                        clean = False
                        print('[' + bcolors.UNICODE_WARNING_2 + '] ........ {} contains a Bucket Policy with READ access for ALL USERS.'.format(bucket_name))
                    if 'PutObject' in statement.get('Action'):
                        clean = False
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains a Bucket Policy with WRITE access for ALL USERS.'.format(bucket_name))
                    if '*' in statement.get('Action'):
                        clean = False
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains a Bucket Policy with FULL CONTROL for ALL USERS.'.format(bucket_name))
        else:
            if '*' in statement.get('Principal') and 'Allow' in statement.get('Effect'):
                bpolicy = True

                if isinstance(statement.get('Action'), list):

                    if any('GetObject' in a for a in statement.get('Action')):
                        clean = False
                        print('[' + bcolors.UNICODE_WARNING_2 + '] ........ {} contains a Bucket Policy with READ access for ALL USERS.'.format(bucket_name))
                    if any('PutObject' in a for a in statement.get('Action')):
                        clean = False
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains a Bucket Policy with WRITE access for ALL USERS.'.format(bucket_name))
                    if any('*' in a for a in statement.get('Action')):
                        clean = False
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains a Bucket Policy with FULL CONTROL for ALL USERS.'.format(bucket_name))
                else:
                    if 'GetObject' in statement.get('Action'):
                        clean = False
                        print('[' + bcolors.UNICODE_WARNING_2 + '] ........ {} contains a Bucket Policy with READ access for ALL USERS.'.format(bucket_name))
                    if 'PutObject' in statement.get('Action'):
                        clean = False
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains a Bucket Policy with WRITE access for ALL USERS.'.format(bucket_name))
                    if '*' in statement.get('Action'):
                        clean = False
                        print('[' + bcolors.UNICODE_FAIL_2 + '] ........ {} contains a Bucket Policy with FULL CONTROL for ALL USERS.'.format(bucket_name))

    if clean == True:
        print('[' + bcolors.UNICODE_PASS_GREEN + '] Bucket enforces least privilege')

    return not clean
