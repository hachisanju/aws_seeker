import subprocess

from seekraux import *
#######################################################################
						#Identify Public Ips#
#######################################################################

def identify_public_ips(profile, secglist, grade):
	print """\033[38;2;255;165;0m             *(*,            
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
                          \033[0;m"""
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

	sec_groups = subprocess.Popen([
		'jq',
		'.Reservations[].Instances[].SecurityGroups',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

	ids = instance_ids.communicate(json_blob)[0]
	groups = sec_groups.communicate(json_blob)[0]

	outlist = out.splitlines()
	idlist = ids.splitlines()
	sec_g_list_2 = groups.split(']')

	public_ips = {}
	for i,j,k in zip(outlist,idlist,sec_g_list_2):
		if i != 'null':
			pub_access = False
			pub_group = False
			i = i.translate(None, '\'\"')
			j = j.translate(None, '\'\"')
			public_ips[j]=i

			print "{} has the public ip {}".format(j, i)

			if len(secglist) > 0:
				del secglist[-1]
				for g,h,m in secglist:
					if g in k:
						print "[" + bcolors.FAIL + u"\u2716" + bcolors.ENDC + "] The instance has the public security group {} attached directly".format(g)
						grade[1]+=2
						for p in h:
							if p != "22":
								print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ Public access allowed to port {}".format(p)
								grade[0]+=3
								grade[1]+=5
							elif p == "22":
								print "[" + bcolors.FAIL + u"\u2716" + bcolors.ENDC + "] ........ Public access allowed to port 22, remediation required"
								grade[1]+=5
						pub_group = True


			shodan_check = subprocess.Popen([
				'curl',
				'https://www.shodan.io/host/{}'.format(i)
				], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			shodan_stream = shodan_check.communicate()[0]
			if "404 Not Found" in shodan_stream:
				print "[" + bcolors.OKBLUE + bcolors.BOLD + u"\u2299" + bcolors.ENDC + "] ........ No hits on Shodan"
				grade[0]+=3
				grade[1]+=3
			else:
				print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ Hit on " + bcolors.UNDERLINE + "https://www.shodan.io/host/{}".format(i) + bcolors.ENDC
				grade[0]+=1
				grade[1]+=3
				service_check(shodan_stream)
				pub_access = True
			if pub_group == False and pub_access == True:
				print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] This instance has no directly attached public security group, but can still be reached from the anywhere on the internet"
				grade[0]+=2
				grade[1]+=3
			elif pub_group == False and pub_access == False:
				print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] This instance is properly situated behind the virtual firewall"
				grade[0]+=5
				grade[1]+=5

			print ""


	return public_ips