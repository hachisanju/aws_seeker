
import subprocess
import datetime
from dateutil import parser

from seekraux import * 




def process_statements(policy_blob, entity, policy_name, policy_type):
	jq_statement = subprocess.Popen([
		'jq',
		'{}'.format(policy_type),
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
	statement = jq_statement.communicate(policy_blob)[0]
	for s in statement.split("}\n{"):
		if s[:1] != "{":
			s = "{" + s
		action = subprocess.Popen([
		'jq',
		'.Action[]',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
		a = action.communicate(s)[0]
		resource = subprocess.Popen([
		'jq',
		'.Resource',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
		r = resource.communicate(s)[0]
		effect = subprocess.Popen([
		'jq',
		'.Effect',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
		e = effect.communicate(s)[0]
		
		if "dynamodb:*" in a and "*" in r and "Allow" in e:
			#print standardized_name
			print "{} has unrestricted DynamoDB access via the policy {}.".format(entity, policy_name)
			

#######################################################################
#######################################################################
					#Identify IAM Policy Status#
#######################################################################
#######################################################################
def output_iam(profile, grade, profile_summary):
	summary = ""
	password_policy_has_issues = False
	role_policies_have_issues = False
	total_users = 0.00
	total_users_with_mfa = 0.00
	total_users_with_attached_policies = 0
	total_default_admins = 0.00
	print """\033[1;32m             .,              
         .*###(//*.          
      .#####%%%#(((//*       
      .###/(*. ,##(///       
     /####//.   ##(////      
     /####//...  ##(////      
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

	role_policies = subprocess.Popen([
    	'aws',
    	'iam',
    	'get-account-authorization-details',
    	'--profile',
    	'{}'.format(profile),
    	], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	role_blob = role_policies.communicate()[0]

#--------------------------------------------------------------
#Setup, grabbing IAM Policies
#--------------------------------------------------------------

	role_details = subprocess.Popen([
		'jq',
		'.RoleDetailList[]',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)	
	user_details = subprocess.Popen([
		'jq',
		'.UserDetailList[]',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
	group_details = subprocess.Popen([
		'jq',
		'.GroupDetailList[]',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

	roles = role_details.communicate(role_blob)[0]
	iamusers = user_details.communicate(role_blob)[0].split("}\n{")
	iamgroups = group_details.communicate(role_blob)[0].split("}\n{")

#--------------------------------------------------------------
#Sorting through roles, but I'm probably going to leave this off the table
#Reading the attached managed policies will grab this info
#--------------------------------------------------------------

	names = []
	details = []
	assumerole = []
	for role in roles.split("}\n{"):
		if not role is roles[-1]:
			role = role+"}"
		if role[:1] != "{":
			role = "{" + role
		if "\"RolePolicyList\": []," not in role:
			n = subprocess.Popen([
				'jq',
				'.RoleName',
				], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
			names.append(n.communicate(role)[0])
			d = subprocess.Popen([
				'jq',
				'.RolePolicyList[]',
				], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
			details.append(d.communicate(role)[0][:-1])
			ar = subprocess.Popen([
				'jq',
				'.AssumeRolePolicyDocument.Statement[].Principal',
				], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
			appenditem = ar.communicate(role)[0][:-1]
			#print appenditem
			if '"AWS":' not in appenditem:
				assumerole.append(appenditem.split(":")[1].replace('[','').replace(']','').replace('{','').replace('}','').replace(' ','').replace('\n', ''))
			else:
				assumerole.append(appenditem.split('"AWS":')[1].replace('[','').replace(']','').replace('{','').replace('}','').replace(' ','').replace('\n', ''))
		

	for n,d,ar in zip(names,details, assumerole):
		if d[:1] != "{":
			d = "{" + d

		policy_name = subprocess.Popen([
			'jq',
			'.PolicyName',
			], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
		name = policy_name.communicate(d)[0]
		standardized_name = name.replace(" ","").replace("\n","")
		process_statements(d, ar ,standardized_name, ".PolicyDocument.Statement[]")
#--------------------------------------------------------------
#Here I'm gonna take a look at the various global account settings and see how they look
#They'll be compared to CIS-CAT standards
#--------------------------------------------------------------
	password_policy = subprocess.Popen([
    	'aws',
    	'iam',
    	'get-account-password-policy',
    	'--profile',
    	'{}'.format(profile),
    	], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

	
	ppolicy=password_policy.communicate()[0]
	if "\"RequireUppercaseCharacters\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Uppercase characters required."

	elif "\"RequireUppercaseCharacters\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Uppercase characters not required."
		password_policy_has_issues = True

	if "\"RequireLowercaseCharacters\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Lowercase characters required."

	elif "\"RequireLowercaseCharacters\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Lowercase characters not required."
		password_policy_has_issues = True

	if "\"RequireSymbols\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Symbol characters required."

	elif "\"RequireSymbols\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Symbol characters not required."
		password_policy_has_issues = True

	if "\"RequireNumbers\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Numeric characters required."

	elif "\"RequireNumbers\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Numeric characters not required."
		password_policy_has_issues = True


	plength = int(ppolicy.split("MinimumPasswordLength\": ")[1].split(",")[0])
	if plength < 14:
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Minimum password length \"{}\" is less than the required 14.".format(str(plength))
		password_policy_has_issues = True

	elif plength >= 14:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Required password length is sufficiently strong."

	if "\"PasswordReusePrevention\":" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Password reuse prevention is enforced."

	else:
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Password reuse prevention is not enforced."
		password_policy_has_issues = True

	if "\"ExpirePasswords\": true" in ppolicy:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Passwords have automatic expiration."

	elif "\"ExpirePasswords\": false":
		print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] Passwords do not have expiration."
		password_policy_has_issues = True

#--------------------------------------------------------------
#Next up it's time to examine the IAM users individually
#--------------------------------------------------------------

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

	#--------------------------------------------------------------------------------------
	#This for loops is going to look at each user and also iterate over their last activity
	#--------------------------------------------------------------------------------------
	
	for user,last in zip(users.communicate(json_blob)[0].split('\n'),activity.communicate(json_blob)[0].split('\n')):
		total_users += 1
		#print user
		isadmin = False
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
					isadmin = True
					print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} has admin privileges for this environment.".format(user)
					total_default_admins += 1
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
					print "[" + bcolors.WARNING + bcolors.BOLD + u"\u2299" + bcolors.ENDC + "] ........ {} has an access key.".format(user)
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
					print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] ........ {} has MFA completely disabled.".format(user)
					if isadmin == True:
						grade[1]+=5
					else:
						grade[1]+=1
				else:
					print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] ........ {} has MFA enabled.".format(user)
					total_users_with_mfa += 1

				#print ""

				#--------------------------------------------------------------
				#This for loop is going to examine their IAM Policies
				#--------------------------------------------------------------
				for iu in iamusers:

					if not iu is iamusers[-1]:
						iu = iu+"}"
					if iu[:1] != "{":
						iu = "{" + iu
					if user in iu:
						#First generate their groups
						user_grouplist = subprocess.Popen([
							'jq',
							'.GroupList[]',
							], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
						gs = user_grouplist.communicate(iu)[0].split("\n")[:-1]

						#Then their managed policies
						managedpolicylist = subprocess.Popen([
							'jq',
							'.AttachedManagedPolicies[].PolicyArn',
							], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
						arns = managedpolicylist.communicate(iu)[0].split("\n")[:-1]
						managedpolicynames = subprocess.Popen([
							'jq',
							'.AttachedManagedPolicies[].PolicyName',
							], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
						policynames = managedpolicynames.communicate(iu)[0].split("\n")[:-1]
						
						#Then iterate over the managed policies
						for arn, pname in zip(arns,policynames):
							getuserpolicy = subprocess.Popen([
								'aws',
								'iam',
								'get-policy-version',
								'--policy-arn',
								'{}'.format(arn.replace("\"", "")),
								'--version-id',
								'v1',
								'--profile',
								'{}'.format(profile),
								], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
							policy_blob = getuserpolicy.communicate()[0]
							if policy_blob.replace(' ','').replace('\n','') != '':
								print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} has a managed policy attached. Policies should typically be delegated by group.".format(user)
								total_users_with_attached_policies += 1
								process_statements(policy_blob, user, pname, ".PolicyVersion.Document.Statement[]")

							#print policy_blob

						#Next, we iterate over each group
						for g in gs:
							for g2 in iamgroups:
								if not g2 is iamgroups[-1]:
									g2 = g2+"}"
								if g2[:1] != "{":
									g2 = "{" + g2
								if g in g2:

									grouppolicylist = subprocess.Popen([
										'jq',
										'.GroupPolicyList',
										], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
									gpl = grouppolicylist.communicate(g2)[0].split("\n")[:-1]

									for gp in gpl:
										gp = gp[1:-1]
										
									managedpolicylist2 = subprocess.Popen([
										'jq',
										'.AttachedManagedPolicies[].PolicyArn',
										], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
									arns2 = managedpolicylist2.communicate(iu)[0].split("\n")[:-1]
									managedpolicynames2 = subprocess.Popen([
										'jq',
										'.AttachedManagedPolicies[].PolicyArn',
										], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
									policynames2 = managedpolicynames2.communicate(iu)[0].split("\n")[:-1]
									
									#Iterate over managed group policies
									for arn2, pnames2 in zip(arns2, policynames2):
										getgrouppolicy = subprocess.Popen([
											'aws',
											'iam',
											'get-policy-version',
											'--policy-arn',
											'{}'.format(arn2.replace("\"", "")),
											'--version-id',
											'v1',
											'--profile',
											'{}'.format(profile),
											], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
										policy_blob2 = getgrouppolicy.communicate()[0]
										#print pnames2
										process_statements(policy_blob2, user, pnames2, ".PolicyVersion.Document.Statement[]")
										#We should do something with these policies
										#print policy_blob2

				print ''

			except ValueError:
				return

	users_with_mfa = (total_users_with_mfa/total_users)*100
	admins = (total_default_admins/total_users)*100
	summary += "{}%% of users have MFA enabled.\n{}%% of users are admins.\n{} policies are directly attached to users.\n".format(users_with_mfa, admins, total_users_with_attached_policies)
	if password_policy_has_issues:
		summary += "Account password policy has issues."
	else:
		summary += "Account password policy is OK."

	#print summary
	profile_summary.iam = summary

	return
