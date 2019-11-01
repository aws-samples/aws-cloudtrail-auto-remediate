# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.  
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Description: Lambda function that restarts CloudTrail logging and sends a notification.
#

import boto3
import logging
import os
import botocore.session
from botocore.exceptions import ClientError
session = botocore.session.get_session()

# Configure lgging
logging.basicConfig(level=logging.INFO)
logger=logging.getLogger(__name__)

# Get the SNS Topic ARN passed in by the environment variable
snsARN = os.environ['SNSTOPIC']

# Lambda function invoked if AWS CloudTrail logging is detected as stopped.
# The function automatically re-enables AWS CloudTrail logging 
# and publishes a notification to an SNS Topic.


# Enable CloudTrail logging
def enable_cloudtrail(trailname):
    client = boto3.client('cloudtrail')
    response = client.start_logging(Name=trailname)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("Response on enable CloudTrail logging - %s" %response)
    else:
        logger.error("Error enabling CloudTrail logging - %s" %response)
    
    return response


# Send notification via SNS
def notify_admin(topic, description):
    snsclient = boto3.client('sns')
    response = snsclient.publish(
        TargetArn = topic,
        Message = "Automatically restarting CloudTrail logging. Event description: \"%s\" " %description,
        Subject = 'CloudTrail Logging Alert'

        )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("SNS notification sent successfully - %s" %response)
    else:
        logger.error("Error sending SNS notification - %s" %response)

    return response


# Lambda entry point
def handler(event, context):

    # Consider setting logging to DEBUG - this function should be rarely invoked, but carefully logged
    logger.setLevel(logging.DEBUG)

    # extract trail ARN by parsing the incoming Security Hub finding (in JSON format)
    trailARN = event['detail']['findings'][0]['ProductFields']['action/awsApiCallAction/affectedResources/AWS::CloudTrail::Trail']
    
    # description contains useful details to be sent to security operations
    description = event['detail']['findings'][0]['Description']

    # If debug logging set, write out details to logs for better audit path
    logger.debug("Event is-- %s" %event)
    logger.debug("trailARN is--- %s" %trailARN)
    logger.debug("snsARN is-- %s" %snsARN)
       
    # Enabling the AWS CloudTrail logging
    try:
        response = enable_cloudtrail(trailARN)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            message = str(description) + " Response - " + str(response) + "."
            notify_admin(snsARN, message)
        else:
            logger.error("Something went wrong - %s, %s" % (response, event))

    except ClientError as e:
        logger.error("An error occured: %s" %e)