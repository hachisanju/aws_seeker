#!/usr/bin/env python

import os
import sys
import argparse
import multiprocessing

from lib.iam import *
from lib.rds import *
from lib.buckets import *
from lib.vulnscan import *
from lib.seekraux import *
from lib.secgroups import *
from lib.publicips import *

class Env_Summary:
	"""Summary Information Related to an entire AWS Environment"""

	iam = "No information"
	security_groups = "No information"
	ec2 = "No information"
	rds = "No information"
	s3 = "No information"


def assess_env(profile, args, grade):
	profile_summary = Env_Summary()
	if args.email:
		print "Please enter gmail username:"
		username = raw_input()
		print "Please enter gmail password:"
		password = raw_input()
		print "Please enter recepient:"
		recepient = raw_input()
	os.system('clear')
		#profile = args.profile
	if args.monitor:
		while True:
			secgs = output_sec_group(profile, grade)
			public_ips = identify_public_ips(profile, secgs, grade)
			p = multiprocessing.Process(target=animate)
			p.start()
			time.sleep(300)
			p.terminate()
	elif args.ec2:
		secgs = output_sec_group(profile, grade)
		public_ips = identify_public_ips(profile, secgs, grade)
	elif args.rds:
		secgs = output_sec_group(profile, grade)
		output_rds(profile, secgs, grade)
	elif args.s3:
		output_buckets(profile, grade)
	elif args.iam:
		output_iam(profile, grade)
	elif args.audit:
		output_iam(profile, grade, profile_summary)
		print profile_summary.iam
		secgs = output_sec_group(profile, grade)
		public_ips = identify_public_ips(profile, secgs, grade)
		output_rds(profile, secgs, grade)
		output_buckets(profile, grade)
		final_score = (grade[0]/grade[1])*100
		final_score = int(final_score)
	return profile_summary

		#sys.exit(0)

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
def main(): 
	#sys.stdout = Logger()
	parser = argparse.ArgumentParser()
	parser.add_argument("--extended", help="perform an extended scan with nmap",
	                    action="store_true")
	parser.add_argument("--monitor", help="monitor only security groups and instances with public ip addresses",
	                    action="store_true")
	parser.add_argument("--audit", help="perform in depth analysis of several components for generating audit scores",
	                    action="store_true")
	parser.add_argument("--ec2", help="audit only ec2 instances (including security groups)",
	                    action="store_true")
	parser.add_argument("--rds", help="audit only rds instances (including security groups)",
	                    action="store_true")
	parser.add_argument("--s3", help="audit only s3 buckets (including acls & bucket policies)",
	                    action="store_true")
	parser.add_argument("--iam", help="audit only iam user information",
	                    action="store_true")
	parser.add_argument("--profile", type=str, help="perform persistent scan of a given profile")
	parser.add_argument("--list", type=str, help="scan all known profiles and provide a summary")
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
		#PREP GRADE
	grade = [0.0, 0.0]
	if args.list:
		with open(args.list, 'r',) as file:
			env_list=file.read()
			p_list = env_list.splitlines()
			print p_list
			profile_summaries = []
			for p in p_list:
				print p
				assess_env(p, args, grade)



	#if args.profile:
		#profile = args.profile

	if args.profile:
		print(assess_env(args.profile, args, grade))
		sys.exit(0)

		'''if args.email:
			print "Please enter gmail username:"
			username = raw_input()
			print "Please enter gmail password:"
			password = raw_input()
			print "Please enter recepient:"
			recepient = raw_input()
		os.system('clear')
		#profile = args.profile
		if args.monitor:
			while True:
				secgs = output_sec_group(profile, grade)
				public_ips = identify_public_ips(profile, secgs, grade)
				p = multiprocessing.Process(target=animate)
				p.start()
				time.sleep(300)
				p.terminate()
		elif args.ec2:
			secgs = output_sec_group(profile, grade)
			public_ips = identify_public_ips(profile, secgs, grade)
		elif args.rds:
			secgs = output_sec_group(profile, grade)
			output_rds(profile, secgs, grade)
		elif args.s3:
			output_buckets(profile, grade)
		elif args.iam:
			output_iam(profile, grade)
		elif args.audit:
			output_iam(profile, grade)
			secgs = output_sec_group(profile, grade)
			public_ips = identify_public_ips(profile, secgs, grade)
			output_rds(profile, secgs, grade)
			output_buckets(profile, grade)
			final_score = (grade[0]/grade[1])*100
			final_score = int(final_score)
			#print "Final Score:"
			#if final_score >= 90:
			#	print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] A {}%".format(final_score)
			#elif final_score >= 80:
			#	print "[" + bcolors.OKGREEN + u"\u2713" + bcolors.ENDC + "] B {}%".format(final_score)
			#elif final_score >= 70:
			#	print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] C {}%".format(final_score)
			#elif final_score >= 60:
			#	print "[" + bcolors.WARNING + bcolors.BOLD + "!" + bcolors.ENDC + "] D {}%".format(final_score)
			#elif final_score < 60:
			#	print "[" + bcolors.FAIL + u"\u2716" + bcolors.ENDC + "] F {}%".format(final_score)
			sys.exit(0)
	#for profile_string in profile_list:
		#try:
			#profile = profile_string.split("[profile ")[1].split("]")[0]
			#output_sec_group(profile)
			#public_ips = identify_public_ips(profile)
			
			#if args.extended:
			#	extended_scan(public_ips)
			#done=True



	#except:''' 
		#sys.exit(0)


if __name__ == "__main__":
	#try:
   	main()
    #except KeyboardInterrupt:
    #	sys.exit()