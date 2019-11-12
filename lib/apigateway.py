import boto3
from .seekraux import *

def api_check(session, region):
    print('Checking region {}...'.format(region['RegionName']))
    api_client = session.client('apigateway', region_name='{}'.format(region['RegionName']))
    apis = api_client.get_rest_apis()['items']
    for api in apis:
        print('Checking settings for {}'.format(api['name']))
        stages = api_client.get_stages(restApiId=api['id'])
        for stage in stages['item']:
            print('........ Checking stage {}'.format(stage['stageName']))
            settings = stage['methodSettings']
            for value in settings.keys():
                setting = settings[value]
                if setting['dataTraceEnabled'] == False:
                    print('[' + bcolors.UNICODE_PASS_GREEN + '] ........ Datatracing (unscrubbed logging) is disabled.')
                else:
                    print('[' + bcolors.UNICODE_FAIL + '] ........ Datatracing (unscrubbed logging) is enabled, and may lead to compliance violations')
            if len(settings.keys()) == 0:
                print('[' + bcolors.UNICODE_WARNING_2 + '] ........ No stage settings found')

######################################################################
                                            #Identify Security Groups#
######################################################################
def output_apigateway(profile, region):
    print(bcolors.OKBLUE + '''
             .-:oo/.
            .+++oyyy-
     .-/+/:.-+++oyyy-`.-:+/-
    +++oyyso++++oyyyyso++syyy
    +++oyo++++++oyyyyyys+syyy
    +++oysoo++++oyyyo+o++syyy
    ::::/+++++++oyyy/:::://++
            .+++oyyy-
    ::/+oooo++++oyyy+//+/+++/
    +++oyysyy+++oyyyysso+syyy
    +++oyo++++++oyyyyyys+syyy
    +++oyyoo++++oyyyyso++syyy
     .-+o/:--+++oyyy:.--:+/-`
            .+++oyyy-
             .-:oo/.
          ''' + bcolors.ENDC)
    print('Checking APIs for {}\n'.format(profile))
    session = boto3.Session(profile_name='{}'.format(profile), region_name=region)
    region_client = session.client('ec2')
    regions = region_client.describe_regions()['Regions']
    for region in regions:
        api_check(session, region)
    return
