import subprocess
import datetime
from dateutil import parser

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

	password_policy = subprocess.Popen([
    	'aws',
    	'iam',
    	'get-account-password-policy',
    	'--profile',
    	'{}'.format(profile),
    	], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	ppolicy=password_policy.communicate()[0]
	if "\"RequireUppercaseCharacters\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Uppercase characters required"
	elif "\"RequireUppercaseCharacters\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Uppercase characters not required"
	if "\"RequireLowercaseCharacters\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Lowercase characters required"
	elif "\"RequireLowercaseCharacters\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Lowercase characters not required"
	if "\"RequireSymbols\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Symbol characters required"
	elif "\"RequireSymbols\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Symbol characters not required"
	if "\"RequireNumbers\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Numeric characters required"
	elif "\"RequireNumbers\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Numeric characters not required"

	plength = int(ppolicy.split("MinimumPasswordLength\": ")[1].split(",")[0])
	if plength < 14:
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Minimum password length \"{}\" is less than the required 14".format(str(plength))
	elif plength >= 14:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Required password length is sufficiently strong"

	if "\"PasswordReusePrevention\":" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Password reuse prevention is enforced"
	else:
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Password reuse prevention is not enforced"
	if "\"ExpirePasswords\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Passwords are expired"
	elif "\"ExpirePasswords\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Passwords are not expired"

	print "\nIAM User Report:\n"
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
		if user != "":
			print "{} IAM user report:".format(user)
		try:
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

			if last != "null":
				dt = parser.parse(last.replace('"', ''))
				#print last
				days = str((datetime.datetime.now() - dt.replace(tzinfo=None))).split(" ")[0]
				if "days" in days:
					idays = int(days)
					if idays >= 90:
						print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] ........ {} has a key that is over 90 days old, and should be terminated.".format(user)

			else:
				print "[" + bcolors.OKBLUE + bcolors.BOLD + u"\u2299" + bcolors.ENDC + "] ........ {} either has no key, or has not used it before.".format(user)
			if "[]" in mfa.communicate()[0]:
				print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] ........ {} has MFA completely disabled".format(user)
			else:
				print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] ........ {} has MFA enabled".format(user)
			print ""
		except ValueError:
			return
	return