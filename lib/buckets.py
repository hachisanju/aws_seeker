import subprocess
import boto3

from seekraux import * 
#######################################################################
					#Identify S3 Buckets#
#######################################################################
def output_buckets(profile, grade):
	print """\033[1;31m            *#(/,            
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
\033[0m"""
	print "Checking S3 Buckets for {}\n".format(profile)
	#s3_output = subprocess.Popen([
    #	'aws',
    #	's3api',
   # 	'list-buckets',
    #	'--profile',
    #	'{}'.format(profile),
    #	], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

	#json_blob = s3_output.communicate()[0]

	#cut_s3 = subprocess.Popen([
	#	'jq',
	#	'.Buckets[].Name',
	#	], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

	#out = cut_s3.communicate(json_blob)[0].split('\n')

	##NEW BOTO3 CALL METHOD:
	session = boto3.Session(profile_name='{}'.format(profile))
	out = session.resource('s3').buckets.all()
	#MUCH SIMPLER

	anywarnings = False
	bacl = False
	bpolicy = False
	for entry in out:
		print "Evaluating ACLs and Bucket Policy for {}".format(entry.name)
		bucket_acl =subprocess.Popen([
    		'aws',
    		's3api',
    		'get-bucket-acl',
    		'--bucket',
    		#'{}'.format(entry.replace('"', '')),
    		'{}'.format(entry.name),
    		'--profile',
    		'{}'.format(profile),
    		], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		acl = bucket_acl.communicate()
		#acl2 = session.resource('s3').BucketAcl('{}'.format(entry)).load()
		#print (acl2)
		clean = True
		for i in range(0,10):
			
			acls = subprocess.Popen([
				'jq',
				'.Grants[{}]'.format(i),
				], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
			value = acls.communicate(acl[0])
				#print value
			if "AllUsers" in "{}".format(value):
				anywarnings = True
				bacl = True
				clean = False
				if "READ" in "{}".format(value):
					print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} contains an ACL with READ access for ALL USERS.".format(entry.name)
					grade[0]+=2
					grade[1]+=3
				if "WRITE" in "{}".format(value):
					print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] ........ {} contains an ACL with WRITE access for ALL USERS.".format(entry.name)
					grade[1]+=5
				if "FULL_CONTROL" in "{}".format(value):
					print "[" + bcolors.FAIL + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} contains an ACL with FULL CONTROL for ALL USERS.".format(entry.name)
					grade[1]+=5
			if "AuthenticatedUsers" in "{}".format(value):
				anywarnings = True
				clean = False
				if "READ" in "{}".format(value):
					print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} contains an ACL with READ access for users within the console.".format(entry.name)
					grade[0]+=2
					grade[1]+=3
				if "WRITE" in "{}".format(value):
					print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} contains an ACL with WRITE access for users within the console.".format(entry.name)
					grade[0]+=2
					grade[1]+=3
				if "FULL_CONTROL" in "{}".format(value):
					print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} contains an ACL with FULL CONTROL for users within the console.".format(entry.name)
					grade[0]+=2
					grade[1]+=3
		
					#i += 1
			#except:
				#break
		#aws s3api list-objects
		objects =subprocess.Popen([
    		'aws',
    		's3api',
    		'list-objects-v2',
    		'--bucket',
    		#'{}'.format(entry.replace('"', '')),
    		'{}'.format(entry.name),
    		'--profile',
    		'{}'.format(profile),
    		"--max-items",
    		"50",
    		], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		#print
		object_blob = objects.communicate()[0]
		#print object_blob
		ob = subprocess.Popen([
		'jq',
		'.Contents[].Key',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
		obj_list = ob.communicate(object_blob)[0].split('\n')
		for o in obj_list:
			if o != "":
				obj_acl =subprocess.Popen([
	    			'aws',
	    			's3api',
	    			'get-object-acl',
	    			'--bucket',
	    			#'{}'.format(entry.replace('"', '')),
	    			'{}'.format(entry.name),
	    			'--profile',
	    			'{}'.format(profile),
	    			'--key',
	    			'{}'.format(o.replace('"', '')),
	    		], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
				objacl = obj_acl.communicate()
				for i in range(0,10):
					oacls = subprocess.Popen([
						'jq',
						'.Grants[{}]'.format(i),
						], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
					ovalue = oacls.communicate(objacl[0])
					#print value
					if "AllUsers" in "{}".format(ovalue):
						clean = False
						if "READ" in "{}".format(ovalue):
							print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ............ {} contains an ACL with READ access for ALL USERS.".format(o)
						if "WRITE" in "{}".format(ovalue):
							print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] ............ {} contains an ACL with WRITE access for ALL USERS.".format(o)
						if "FULL_CONTROL" in "{}".format(ovalue):
							print "[" + bcolors.FAIL + bcolors.BOLD + u"\u2716" + bcolors.ENDC + "] ............ {} contains an ACL with FULL CONTROL for ALL USERS.".format(o)

	#out = cut_s3.communicate(json_blob)[0].split('\n')

		bucket_policy =subprocess.Popen([
    		'aws',
    		's3api',
    		'get-bucket-policy',
    		'--bucket',
    		#'{}'.format(entry.replace('"', '')),
    		'{}'.format(entry.name),
    		'--profile',
    		'{}'.format(profile),
    		'--output',
    		'text',
    		], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		policy = bucket_policy.communicate()[0]
		bps = subprocess.Popen([
			'jq',
			'.Statement[].Effect',
			], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
		effect = bps.communicate(policy)[0].split('\n')
		bps = subprocess.Popen([
			'jq',
			'.Statement[].Principal',
			], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
		principal = bps.communicate(policy)[0].split('}\n{')
		bps = subprocess.Popen([
			'jq',
			'.Statement[].Action',
			], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
		actions = bps.communicate(policy)[0].split('\n')
		for e,p,a in zip(effect,principal,actions):
			if "\"*\"" in p and "Allow" in e:
				bpolicy = True

				if "GetObject" in a:
					clean = False
					print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} contains a Bucket Policy with READ access for ALL USERS.".format(entry.name)
				if "PutObject" in a:
					clean = False
					print "[" + bcolors.FAIL + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} contains a Bucket Policy with WRITE access for ALL USERS.".format(entry.name)
				if "*" in a:
					clean = False
					print "[" + bcolors.FAIL + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ {} contains a Bucket Policy with FULL CONTROL for ALL USERS.".format(entry.name)

		if clean == True:
			print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] Bucket enforces least privilege"

		print ""

	if bacl == False:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] No S3 Buckets with public ACLs have been identified."
		grade[0]+=10
		grade[1]+=10
	if bpolicy == False:
		print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] No S3 Buckets with public Bucket Policies have been identified."
		grade[0]+=10
		grade[1]+=10

	print""

	return

	#if out != '':
		#print "[" + bcolors.FAIL + u"\u2716" + bcolors.ENDC + "] Public security groups identified. Please remediate immediately:"
		#print "{}\n".format(out)
		#if args.email:
			#send_warning(profile, "Public security groups identified. Please remediate immediately.", out)
	#else:
		#print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] No security groups with public rules have been identified.\n"
	#return