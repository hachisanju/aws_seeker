import subprocess

from seekraux import *
#######################################################################
						#Identify Public Ips#
#######################################################################

def identify_public_ips(profile):
	print """             *(*,            
         */**##////*,        
     .#//#(//##/////////,    
   ///#//#(//##///////////*  
   (//#//#(//##///////////*  
   ///#//#(//##///////////*  
   ///#//#(//##///////////*  
   ///#//#(//##///////////*  
   ///#//#(//##///////////*  
   ///#//#(//##///////////*  
   ///#//#(//##///////////*  
   .,,#//#(//##//////////*   
         #(//##//////*       
            .##//,           
                          """
	print "Checking Public Instances for {}\n".format(profile)
	public_ip_output = subprocess.Popen([
		'aws',
		'ec2',
		'describe-instances',
		'--filters',
		'Name=instance-state-name,Values=running',
		'--profile',
		'{}'.format(profile),
		], stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

	json_blob = public_ip_output.communicate()[0]

	cut_ips = subprocess.Popen([
		'jq',
		'.Reservations[].Instances[].PublicIpAddress',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

	out = cut_ips.communicate(json_blob)[0]

	instance_ids = subprocess.Popen([
		'jq',
		'.Reservations[].Instances[].InstanceId',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

	ids = instance_ids.communicate(json_blob)[0]

	outlist = out.splitlines()
	idlist = ids.splitlines()

	public_ips = {}
	for i,j in zip(outlist,idlist):
		if i != 'null':
			i = i.translate(None, '\'\"')
			j = j.translate(None, '\'\"')
			public_ips[j]=i

			print "{} has the public ip {}".format(j, i)

			shodan_check = subprocess.Popen([
				'curl',
				'https://www.shodan.io/host/{}'.format(i)
				], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			shodan_stream = shodan_check.communicate()[0]
			if "404 Not Found" in shodan_stream:
				print "[" + bcolors.OKBLUE + bcolors.BOLD + u"\u2299" + bcolors.ENDC + "] ........ No hits on Shodan\n"
			else:
				print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ Hit on " + bcolors.UNDERLINE + "https://www.shodan.io/host/{}\n".format(i) + bcolors.ENDC
				service_check(shodan_stream)

	#print public_ips
	return public_ips