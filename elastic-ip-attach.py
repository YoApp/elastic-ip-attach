#!/usr/bin/python2

import argparse
import os
import signal
import sys
import time

import boto.ec2.elb
import requests

parser = argparse.ArgumentParser(
        description="Associate an Elastic IP to the local EC2 instance.")

parser.add_argument('--public-ip',
        metavar='<PUBLIC_IP>',
        default=os.environ.get('PUBLIC_IP'),
        help='Public IP address of Elastic IP to associate with')
parser.add_argument('--region',
        metavar='<REGION>',
        default=os.environ.get('REGION'),
        help='AWS region in which the Elastic IP resides')
parser.add_argument('--access-key',
        metavar='<ACCESS>',
        default=os.environ.get('AWS_ACCESS_KEY'))
parser.add_argument('--secret-key',
        metavar='<SECRET>',
        default=os.environ.get('AWS_SECRET_KEY'))

args = parser.parse_args()

conn = boto.ec2.connect_to_region(
        region_name = args.region,
        aws_access_key_id = args.access_key,
        aws_secret_access_key = args.secret_key
        )

instance = requests.get(
    'http://169.254.169.254/latest/meta-data/instance-id').content

print "Associating instance {} to Elastic IP {}".format(instance,
        args.public_ip)
conn.associate_address(instance, args.public_ip)

def disassociate_func(public_ip):
    def handler(*args, **kwargs):
        print "Disassociating instance {} from Elastic IP {}".format(instance,
                public_ip)
        conn.disassociate_address(public_ip)
        sys.exit(0)
    return handler

disassociate = disassociate_func(args.public_ip)
signal.signal(signal.SIGTERM, disassociate)
signal.signal(signal.SIGINT, disassociate)

while True:
    time.sleep(5)
