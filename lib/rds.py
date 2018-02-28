import subprocess

from seekraux import * 
#######################################################################
					#Identify Security Groups#
#######################################################################
def output_rds(profile, secglist, grade):
  print bcolors.OKBLUE + """      
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
          """ + bcolors.ENDC
  print "Checking RDS instances for {}\n".format(profile)

  regions_output = subprocess.Popen([
    'aws',
    'ec2',
    'describe-regions',
    '--output',
    'text',
    '--profile',
    '{}'.format(profile),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  cut_regions = subprocess.Popen([
    'cut',
    '-f3',
    ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
  regions = cut_regions.communicate(regions_output.communicate()[0])[0]
  for region in regions.splitlines():
    print "Checking region {}...".format(region)
    
    public_rds_output = subprocess.Popen([
      'aws',
      'rds',
      'describe-db-instances',
      '--filters',
      '--profile',
      '{}'.format(profile),
      '--region',
      '{}'.format(region)
      ], stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    json_blob = public_rds_output.communicate()[0] 

    rds_name = subprocess.Popen([
    'jq',
    '.DBInstances[].DBInstanceIdentifier',
    ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    name = rds_name.communicate(json_blob)[0].split('\n')

    rds_add = subprocess.Popen([
    'jq',
    '.DBInstances[].Endpoint.Address',
    ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    address = rds_add.communicate(json_blob)[0].split('\n')
    
    rds_port = subprocess.Popen([
    'jq',
    '.DBInstances[].Endpoint.Port',
    ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    port = rds_port.communicate(json_blob)[0].split('\n')

    rds_enc = subprocess.Popen([
    'jq',
    '.DBInstances[].StorageEncrypted',
    ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    encrypted = rds_enc.communicate(json_blob)[0].split('\n')

    rds_pub = subprocess.Popen([
    'jq',
    '.DBInstances[].PubliclyAccessible',
    ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    public = rds_pub.communicate(json_blob)[0].split('\n')

    rds_secgs = subprocess.Popen([
    'jq',
    '.DBInstances[].VpcSecurityGroups',
    ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    securitygs = rds_secgs.communicate(json_blob)[0].split(']\n[')
    #print securitygs

    for n,a,po,e,pu,s in zip(name,address,port,encrypted,public,securitygs):
      if n != "":
        print "Evaluating controls for {}".format(n)
        print "[" + bcolors.OKBLUE + bcolors.BOLD + u"\u2299" + bcolors.ENDC + "] ........ DB is accessed via {}:{}".format(a.replace('"',''),po)
        if e == "false":
          print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ Storage for DB is not encrypted"
          grade[0]+=3
          grade[1]+=5
        elif e == "true":
          print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] ........ Storage for DB is encrypted"
          grade[0]+=5
          grade[1]+=5

        if pu == "false":
          print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] ........ DB is not publicly accessible"
          grade[0]+=3
          grade[1]+=3
        elif pu == "true":
          print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ DB is publicly accessible"
          grade[0]+=1
          grade[1]+=3
        #print secglist
        for i,j,k in secglist:
          if k.replace('"', '') in s and k != '':
            print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] ............ RDS instance has public security group attached"
            grade[1]+=5
      else:
        print "No RDS instances identified."
    print ""

  print "Checking DynamoDB instances for {}\n".format(profile)

  regions_output = subprocess.Popen([
    'aws',
    'ec2',
    'describe-regions',
    '--output',
    'text',
    '--profile',
    '{}'.format(profile),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  cut_regions = subprocess.Popen([
    'cut',
    '-f3',
    ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
  regions = cut_regions.communicate(regions_output.communicate()[0])[0]
  for region in regions.splitlines():
    print "Checking region {}...".format(region)
    '''
    public_dynamodb_output = subprocess.Popen([
      'aws',
      'dynamodb',
      'list-tables',
      '--profile',
      '{}'.format(profile),
      '--region',
      '{}'.format(region)
      ], stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    json_blob = public_dynamodb_output.communicate()[0] 
    #print(json_blob)

    dynamodb_name = subprocess.Popen([
    'jq',
    '.TableNames[]',
    ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    names = dynamodb_name.communicate(json_blob)[0].split('\n')
    print names
    for name in names:
      print name
      print profile
      print region
      describe_output = subprocess.Popen([
        'aws',
        'dynamodb',
        'describe-table',
        '--table-name',
        '{}'.format(name.replace('"', '')),
        '--profile',
        '{}'.format(profile),
        '--region',
        '{}'.format(region)
        ], stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
      describe_blob = describe_output.communicate()[0]
      print (describe_blob)
      
      arn_process = subprocess.Popen([
      'jq',
      '.Table.TableArn',
      ], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

      arn = arn_process.communicate(describe_blob)[0]
      print (arn)'''

    #rds_add = subprocess.Popen([
    #'jq',
    #'.DBInstances[].Endpoint.Address',
    #], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    #address = rds_add.communicate(json_blob)[0].split('\n')
    
    #rds_port = subprocess.Popen([
    #'jq',
    #'.DBInstances[].Endpoint.Port',
    #], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    #port = rds_port.communicate(json_blob)[0].split('\n')

    #rds_enc = subprocess.Popen([
    #'jq',
    #'.DBInstances[].StorageEncrypted',
    #], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    #encrypted = rds_enc.communicate(json_blob)[0].split('\n')

    #rds_pub = subprocess.Popen([
    #'jq',
    #'.DBInstances[].PubliclyAccessible',
    #], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

    #public = rds_pub.communicate(json_blob)[0].split('\n')

    #rds_secgs = subprocess.Popen([
    #'jq',
    #'.DBInstances[].VpcSecurityGroups',
    #], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

#    securitygs = rds_secgs.communicate(json_blob)[0].split(']\n[')
  return

