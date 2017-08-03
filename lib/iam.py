import subprocess

from seekraux import * 
#######################################################################
					#Identify IAM Policy Status#
#######################################################################
def output_iam(profile):
	print """\033[1;32m             .,              
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
           \033[0m"""
	print "Checking IAM Policies for {}\n".format(profile)
	iam_output = subprocess.Popen([
    	'aws',
    	'iam',
    	'list-users',
    	'--profile',
    	'{}'.format(profile),
    	], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	json_blob = iam_output.communicate()[0]

	users = subprocess.Popen([
		'jq',
		'.Users[].UserName',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
	activity = subprocess.Popen([
		'jq',
		'.Users[].PasswordLastUsed',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
	for user,last in zip(users.communicate(json_blob)[0].split('\n'),activity.communicate(json_blob)[0].split('\n')):
		#print user
		#print last
		groups = subprocess.Popen([
    		'aws',
    		'iam',
    		'list-groups-for-user',
    		'--user-name',
    		'{}'.format(user.replace('"', '')),
    		'--profile',
    		'{}'.format(profile),
    		], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		if "admin" in groups.communicate()[0]:
			print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} has admin privileges for this environment".format(user)
		mfa = subprocess.Popen([
    		'aws',
    		'iam',
    		'list-mfa-devices',
    		'--user-name',
    		'{}'.format(user.replace('"', '')),
    		'--profile',
    		'{}'.format(profile),
    		], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		if "[]" in mfa.communicate()[0]:
			print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] ........ {} has MFA completely disabled".format(user)

	return