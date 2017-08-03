#!/usr/bin/env python

import os
import sys
import argparse
import multiprocessing

from lib.iam import *
from lib.buckets import *
from lib.vulnscan import *
from lib.seekraux import *
from lib.secgroups import *
from lib.publicips import *

#######################################################################
#'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''#
#                                                                     #
#######################################################################
								#Main#
#######################################################################
#                                                                     #
#.....................................................................#
#######################################################################

#First generate the list of all profiles
parser = argparse.ArgumentParser()
parser.add_argument("--extended", help="perform an extended scan with nmap",
                    action="store_true")
parser.add_argument("--monitor", help="monitor only security groups and instances with public ip addresses",
                    action="store_true")
parser.add_argument("--audit", help="perform in depth analysis of several components for generating audit scores",
                    action="store_true")
parser.add_argument("--profile", type=str, help="perform persistent scan of a given profile")
parser.add_argument("--email", help="send email warnings",
                    action="store_true")
args = parser.parse_args()

profile_output = subprocess.Popen([
	'cat',
	'{}/.aws/config'.format(os.environ['HOME']),
	], stdout=subprocess.PIPE)
profile_o = profile_output.communicate()[0]
profiles = subprocess.Popen([
	'grep',
	'profile',
	], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
profile_list= profiles.communicate(profile_o)

if args.profile:
	if args.email:
		print "Please enter gmail username:"
		username = raw_input()
		print "Please enter gmail password:"
		password = raw_input()
		print "Please enter recepient:"
		recepient = raw_input()
	os.system('clear')
	if args.monitor:
		while True:
			profile = args.profile
			output_sec_group(profile)
			public_ips = identify_public_ips(profile)
			p = multiprocessing.Process(target=animate)
			p.start()
			time.sleep(300)
			p.terminate()
	elif args.audit:
		
		profile = args.profile
		output_iam(profile)
		output_sec_group(profile)
		public_ips = identify_public_ips(profile)
		output_buckets(profile)


#for profile_string in profile_list:
	#try:
		#profile = profile_string.split("[profile ")[1].split("]")[0]
		#output_sec_group(profile)
		#public_ips = identify_public_ips(profile)
		
		#if args.extended:
		#	extended_scan(public_ips)
		#done=True



	#except:
		#sys.exit(0)
	sys.exit(0)

if __name__ == "__main__":
    main()