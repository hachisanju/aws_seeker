import subprocess

from seekraux import * 
#######################################################################
					#Identify Security Groups#
#######################################################################
def output_sec_group(profile, grade):
	print bcolors.WARNING + """           ,,. ,,.           
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
          """ + bcolors.ENDC
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
	cut_sec_ports = subprocess.Popen([
		'jq',
		'.SecurityGroups[].IpPermissions',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)
	group_id= subprocess.Popen([
		'jq',
		'.SecurityGroups[].GroupId',
		], stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr=subprocess.STDOUT)

	out = cut_sec_groups.communicate(json_blob)[0]
	ports = cut_sec_ports.communicate(json_blob)[0]
	group = group_id.communicate(json_blob)[0]

	sec_port_list = []
	for i,j,k in zip(out.split('\n'),ports.split(']\n['),group.split('\n')):
		port_list = []

		for line in j.split('\n'):
			if "ToPort" in line:
				port_list.append(line.split("ToPort\": ")[1].split(",")[0])

		if "CidrIp" in json_blob:
			print "Results for {}".format(i)
			print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] This security group has public access allowed on one or more ports"
			for p in port_list:
				if p != "22":
					print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] ........ Public access allowed to port {}".format(p)
					grade[0]+=3
					grade[1]+=4
				elif p == "22":
					print "[" + bcolors.FAIL + u"\u2716" + bcolors.ENDC + "] ........ Public access allowed to port 22, remediation required"
					grade[1]+=4
			#print "{}\n".format(out)
			#if args.email:
				#send_warning(profile, "Public security groups identified. Please remediate immediately.", out)
		else:
			print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] No security groups with public rules have been identified.\n"
			grade[1]+=3
			grade[0]+=3

		sec_port_list.append(port_list)
	ret = zip(out.split('\n'),sec_port_list,group.split('\n'))
	print ""

	return ret