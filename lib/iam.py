#!/usr/bin/python
import datetime
import boto3
import pytz
from .seekraux import bcolors

#----------------------------------------------------------------------
#Setup: CONSTANTS
#----------------------------------------------------------------------

#######################################################################
#######################################################################
            #Identify IAM Policy Status#
#######################################################################
#######################################################################
def output_iam(profile, profile_summary, region):
    print('''\033[1;32m             .,
         .*###(//*.
      .#####%%%#(((//*
      .###/(*. ,##(///
     /####//.   ##(////
     /####//... ##(////
     .*#######(///////,
      .#((####(//(///*
          (###(///.
          (###(///////
          (###(/////,.
          (###(/////.
          (###(/,
          (###(//*//.
          (###(/////
           .##(/,
           \033[0m''')
    print('Checking IAM Policies for {}\n'.format(profile))

    session = boto3.Session(profile_name='{}'.format(profile), region_name=region)
    iam_client = session.client('iam')

#--------------------------------------------------------------
#Setup: lists used to provide IAM metadata
#--------------------------------------------------------------
    summary = ''
    total_users = 0.00
    total_users_with_mfa = []
    total_default_admins = []
    total_users_attached_policies = []

    pw_pol_has_issues = pw_policy_check(iam_client)
#--------------------------------------------------------------
#Next up it's time to examine the IAM users individually
#--------------------------------------------------------------
    print('\nIAM User Report:\n')

    iam_users = iam_client.list_users().get('Users')

    for user in iam_users:
        total_users += 1
        user_name = user.get('UserName')
        user_id = user.get('UserId')
        pw_last_used = user.get('PasswordLastUsed')

        print('{} IAM user report:'.format(user_name))

        if user:
            if mfa_device_check(user_name, user_id, iam_client) is True:
                total_users_with_mfa.append(user_name)
            if user_group_check(user_name, iam_client) is True:
                total_default_admins.append(user_name)
            if user_attached_policies_check(user_name, iam_client) is True:
                total_users_attached_policies.append(user_name)

            user_console_access_check(user_name, pw_last_used)

        print('')

    users_with_mfa = (len(total_users_with_mfa)/total_users)*100
    admins = (len(total_default_admins)/total_users)*100
    summary = '''{}%% of users have MFA enabled.
                \n{}%% of users are admins.
                \n{} policies are directly attached to users.
                \n'''.format(users_with_mfa, admins, len(total_users_attached_policies))
    if pw_pol_has_issues:
        summary += 'Account password policy has issues.'
    else:
        summary += 'Account password policy is OK.'
    profile_summary.iam = summary

    return

def pw_policy_check(client):
    #--------------------------------------------------------------
    #Here we take a look at the various global account settings and see how they look.
    #They'll be compared to CIS-CAT standards.
    #--------------------------------------------------------------
    account_pw_policy = client.get_account_password_policy().get('PasswordPolicy')
    min_pw_length = str(account_pw_policy.get('MinimumPasswordLength'))

    pw_pol_has_issues = False

    if account_pw_policy.get('MinimumPasswordLength') < 14:
        pw_pol_has_issues = True
        print('[' + bcolors.UNICODE_FAIL + '''] Minimum password length \'{}\' is less than the required 14.'''.format(min_pw_length))

    if account_pw_policy.get('MinimumPasswordLength') >= 14:
        print('[' + bcolors.UNICODE_PASS_GREEN + '] Required password length is sufficiently strong.')

    if account_pw_policy.get('RequireUppercaseCharacters'):
        print('[' + bcolors.UNICODE_PASS_GREEN + '] Uppercase characters required.')

    else:
        pw_pol_has_issues = True
        print('[' + bcolors.UNICODE_FAIL + '] Uppercase characters not required.')

    if account_pw_policy.get('RequireLowercaseCharacters'):
        print('[' + bcolors.UNICODE_PASS_GREEN + '] Lowercase characters required.')
    else:
        pw_pol_has_issues = True
        print('[' + bcolors.UNICODE_FAIL + '] Lowercase characters not required.')

    if account_pw_policy.get('RequireSymbols'):
        print('[' + bcolors.UNICODE_PASS_GREEN + '] Symbol characters required.')
    else:
        pw_pol_has_issues = True
        print('[' + bcolors.UNICODE_FAIL + '] Symbol characters not required.')

    if account_pw_policy.get('RequireNumbers'):
        print('[' + bcolors.UNICODE_PASS_GREEN + '] Numeric characters required.')
    else:
        pw_pol_has_issues = True
        print('[' + bcolors.UNICODE_FAIL + '] Numeric characters not required.')

    if account_pw_policy.get('PasswordReusePrevention'):
        print('[' + bcolors.UNICODE_PASS_GREEN + '] Password reuse prevention is enforced.')
    else:
        pw_pol_has_issues = True
        print('[' + bcolors.UNICODE_FAIL + '] Password reuse prevention is not enforced.')

    if account_pw_policy.get('ExpirePasswords'):
        print('[' + bcolors.UNICODE_PASS_GREEN + '] Passwords have automatic expiration.')
    else:
        pw_pol_has_issues = True
        print('[' + bcolors.UNICODE_FAIL + '] Passwords do not have expiration.')

    return pw_pol_has_issues

def mfa_device_check(user_name, user_id, client):
#--------------------------------------------------------------
#Examining the given user's mfa status
#Returns if user has mfa enabled
#--------------------------------------------------------------
    all_virtual_mfa_devices = client.list_virtual_mfa_devices().get('VirtualMFADevices')
    user_mfa_devices = client.list_mfa_devices(UserName=user_name).get('MFADevices')
    user_has_virtual_mfa = False
    is_mfa_enabled = False

    for device in all_virtual_mfa_devices:
        if device.get('User') and device.get('UserId') == user_id:
            user_has_virtual_mfa = True

    if user_has_virtual_mfa or user_mfa_devices:
        is_mfa_enabled = True
        print('[' + bcolors.UNICODE_PASS_BLUE + '] ........ {} has at least one mfa device'.format(user_name))
    else:
        print('[' + bcolors.UNICODE_FAIL + '] ........ {} does not have mfa enabled'.format(user_name))

    return is_mfa_enabled

def user_console_access_check(user_name, pw_last_used):
#--------------------------------------------------------------
#Examining user AWS console access
#Prints if a user has a key, if the key is >=90 days, or if user
#has no key.
#--------------------------------------------------------------
    if pw_last_used:
        days = (datetime.datetime.now(pytz.utc) - pw_last_used).days

        print('[' + bcolors.UNICODE_WARNING + '] ........ {} has an access key.'.format(user_name))

        if days >= 90:
            print('[' + bcolors.UNICODE_FAIL + '] ........ {} has a key that is over 90 days old, and should be terminated.'.format(user_name))
        else:
            print('[' + bcolors.UNICODE_PASS_BLUE + '] ........ {} either has no key, or has not used it before.'.format(user_name))
    else:
        print('[' + bcolors.UNICODE_PASS_BLUE + '] ........ {} either has no key, or has not used it before.'.format(user_name))

def user_attached_policies_check(user_name, client):
#--------------------------------------------------------------
#Examining user-attached policies
#Returns number of users w/ attached policies
#--------------------------------------------------------------
    attached_user_policies = client.list_attached_user_policies(UserName=user_name).get('AttachedPolicies')
    user_has_attached_policy = False

    if attached_user_policies:
        user_has_attached_policy = True
        policies = []
        for policy in attached_user_policies:
            policies.append(policy.get('PolicyName'))
        print('[' + bcolors.UNICODE_FAIL + '] ........ {} has the following attached policies that should be moved to group or role: {}.'.format(user_name, policies))

    return user_has_attached_policy

def user_group_check(user_name, client):
#------------------------------------------------------------------
#Examining groups attached to individual user for * DynamoDB access
#Also examines number of admins
#Returns number of admins
#------------------------------------------------------------------
    current_user_groups = client.list_groups_for_user(UserName=user_name)
    names_of_admin_groups = ['admin', 'admins', 'administrator', 'administrators']
    is_admin = False

    for group in current_user_groups.get('Groups'):
        if group:
            group_name = group.get('GroupName')

            if any(x in group_name for x in names_of_admin_groups):
                is_admin = True

                print('[' + bcolors.UNICODE_WARNING_2 + '] ........ {} has admin privileges for this environment.'.format(user_name))

            inline_group_policies = client.list_group_policies(GroupName=group_name).get('PolicyNames')
            attached_group_policies = client.list_attached_group_policies(GroupName=group_name).get('AttachedPolicies')

            for inline in inline_group_policies:
                if inline:
                    inline_policy_details = client.get_group_policy(GroupName=group_name, PolicyName=inline).get('PolicyDocument')

                    if inline_policy_details:
                        print('[' + bcolors.UNICODE_WARNING_2 + '] ........ the {} group has INLINE permissions via {}.'.format(group_name, inline))
                        for statement in inline_policy_details.get('Statement'):
                            try:
                                if any('dynamodb:*' in s for s in statement.get('Action')) and '*' in str(statement.get('Resource')) and 'Allow' in statement.get('Effect'):
                                    print('[' + bcolors.UNICODE_WARNING_2 + '] ........ {} has unrestricted DynamoDB access via the INLINE policy {}'.format(user_name, inline))
                            except:
                                print('    ........ No statement defined.')
            for attached in attached_group_policies:
                if attached:
                    attached_policy_arn = attached.get('PolicyArn')
                    attached_policy_version_id = client.get_policy(PolicyArn=attached_policy_arn).get('Policy').get('DefaultVersionId')
                    attached_policy_document = client.get_policy_version(PolicyArn=attached_policy_arn, VersionId=attached_policy_version_id).get('PolicyVersion').get('Document')

                    for statement in attached_policy_document.get('Statement'):
                        if statement.get('Action'):
                            try:
                                if any('dynamodb:*' in s for s in statement.get('Action')) and '*' in str(statement.get('Resource')) and 'Allow' in statement.get('Effect'):
                                    print('[' + bcolors.UNICODE_WARNING_2 +  '] ........ {} has unrestricted DynamoDB access via the MANAGED policy {}'.format(user_name, attached.get('PolicyName')))
                            except:
                                print('    ........ No statement defined.')
    return is_admin
