#!/usr/bin/env python

import os
import sys
import signal
import argparse
import multiprocessing

from lib.iam import *
from lib.rds import *
from lib.buckets import *
from lib.seekraux import *
from lib.secgroups import *
from lib.publicips import *
from lib.apigateway import *
from lib.resourcemodule import *


class Env_Summary:
    """Summary Information Related to an entire AWS Environment"""
    iam = "No information"
    security_groups = "No information"
    ec2 = "No information"
    rds = "No information"
    s3 = "No information"

def signal_handler(sig, frame):
    print('\nExiting...\n')
    sys.exit(0)

def assess_env(profile, args, region='us-east-2'):
    profile_summary = Env_Summary()

    if args.monitor:
        while True:
            secgs = output_sec_group(profile, region)
            public_ips = identify_public_ips(profile, secgs, region)
            p = multiprocessing.Process(target=animate)
            p.start()
            time.sleep(300)
            p.terminate()
    elif args.ec2:
        secgs = output_sec_group(profile, region)
        public_ips = identify_public_ips(profile, secgs, region)
        list_ec2(public_ips)
    elif args.rds:
        secgs = output_sec_group(profile, region)
        output_rds(profile, secgs, region)
    elif args.s3:
        output_buckets(profile, region)
    elif args.iam:
        output_iam(profile, profile_summary, region)
    elif args.apigateway:
        output_apigateway(profile, region)
    elif args.audit:
        output_iam(profile, profile_summary, region)
        print(profile_summary.iam)
        secgs = output_sec_group(profile, region)
        for group in secgs:
            group.output_summary()
            group.output_details()
        public_ips = identify_public_ips(profile, secgs, region)
        for ip in public_ips:
            ip.output_summary()
            ip.output_details()
        output_rds(profile, secgs, region)
        output_buckets(profile, region)
    return profile_summary

def list_ec2(ec2_list):
    action = ''
    while action != 'exit':
        os.system('cls' if os.name == 'nt' else 'clear')
        print("EC2 Instances with public IPs.\n")
        for ec2 in ec2_list:
            ec2.output_summary()
            print('')
        print("Input instance name for details.")
        print("Input 'exit' to terminate.\n")
        action = raw_input(">>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print("EC2 Instance details.\n")
        for ec2 in ec2_list:
            if ec2.instanceName == action:
                ec2.output_summary()
                ec2.output_details()
        print ("Input 'back' to go back.")
        #print("Input 'exit' to terminate.\n")
        action = raw_input(">>> ")

#######################################################################
#'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''#
#                                                                     #
#######################################################################
#Main#
#######################################################################
#                                                                     #
#.....................................................................#
#######################################################################


# First generate the list of all profiles
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--extended", help="perform an extended scan with nmap", action="store_true")
    parser.add_argument("--monitor", help="monitor only security groups and instances with public ip addresses", action="store_true")
    parser.add_argument("--audit", help="perform in depth analysis of several components for generating audit scores", action="store_true")
    parser.add_argument("--ec2", help="audit only ec2 instances (including security groups)", action="store_true")
    parser.add_argument("--rds", help="audit only rds instances (including security groups)", action="store_true")
    parser.add_argument("--s3", help="audit only s3 buckets (including acls & bucket policies)", action="store_true")
    parser.add_argument("--iam", help="audit only iam user information", action="store_true")
    parser.add_argument("--apigateway", help="audit only api information", action="store_true")
    parser.add_argument("--profile", type=str, help="perform persistent scan of a given profile")
    parser.add_argument("--region", type=str, help="primary AWS region to create api session in")
    parser.add_argument("--list", type=str, help="scan all known profiles and provide a summary")
    parser.add_argument("--email", help="send email warnings", action="store_true")
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
    profile_list = profiles.communicate(profile_o)
    grade = [0.0, 0.0]
    if args.list:
        with open(args.list, 'r',) as file:
            env_list = file.read()
            p_list = env_list.splitlines()
            print(p_list)
            for p in p_list:
                print(p)
                assess_env(p, args)

    if args.profile:
        if args.region:
            assess_env(args.profile, args, args.region)
        else:
            assess_env(args.profile, args)
        sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
