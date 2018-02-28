# aws_seeker

The AWS CLI and the boto3 library are required. boto3 can be installed using pip install boto3.

This script has only been tested on Ubuntu and MacOSX, and it's very hacky.

This application is READ ONLY but can be executed by any IAM user with READ or WRITE permissions. If you're afraid of the script accidentally doing something bad (which I promise it doesn't), create a new IAM user with only READ permissions.

./aws_seeker --audit --profile <PROFILE_NAME> is the preferred invocation. This reports all criteria directly to your command line. --audit can be replaced with --monitor, which will consistently assess security groups and ec2 instances every 5 minutes. For now, every other flag should not be used.

