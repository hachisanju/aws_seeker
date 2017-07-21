import subprocess

from seekraux import * 
#######################################################################
					#Identify Security Groups#
#######################################################################
def output_sec_group(profile):
	print """           ,,. ,,.           
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
          """
	print "Checking Security Groups for {}\n".format(profile)
	sec_group_output = subprocess.Popen([
    	'aws',
    	'ec2',
    	'describe-security-groups',
    	'--filters',
    	'Name=ip-permission.cidr,Values=0.0.0.0/0',
    	'--profile',
    	'{}'.format(profile),
    	], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

	json_blob = sec_group_output.communicate()[0]

	cut_sec_groups = subprocess.Popen([
		'jq',
		'.SecurityGroups[].GroupName',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

	out = cut_sec_groups.communicate(json_blob)[0]

	if out != '':
		print "[" + bcolors.FAIL + u"\u2716" + bcolors.ENDC + "] Public security groups identified. Please remediate immediately:"
		print "{}\n".format(out)
		#if args.email:
			#send_warning(profile, "Public security groups identified. Please remediate immediately.", out)
	else:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] No security groups with public rules have been identified.\n"
	return