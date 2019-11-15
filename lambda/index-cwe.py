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

# Description: Lambda function that restarts CloudTrail if logging and sends a notification in response to CloudTrail StopLogging.
#

import boto3
import logging
import os
import botocore.session
from botocore.exceptions import ClientError
session = botocore.session.get_session()

# Configure lgging
logger=logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Get the SNS Topic ARN passed in by the environment variable
snsARN = os.environ['SNSTOPIC']

# Lambda function invoked if AWS CloudTrail logging is detected as stopped.
# The function automatically re-enables AWS CloudTrail logging 
# and publishes a notification to an SNS Topic.


# Get CloudTrail logging Status
def get_cloudtrail_status(trailname):
    client = boto3.client('cloudtrail')
    response = client.get_trail_status(Name=trailname)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        response = response['IsLogging']
        logger.info("Status of CloudTrail logging for %s - %s" % (trailname, response))
    else:
        logger.error("Error gettingCloudTrail logging status for %s - %s" % (trailname, response))
    
    return response


# Enable CloudTrail logging
def enable_cloudtrail(trailname):
    client = boto3.client('cloudtrail')
    response = client.start_logging(Name=trailname)

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("Response on enable CloudTrail logging for %s - %s" % (trailname, response))
    else:
        logger.error("Error enabling CloudTrail logging for %s - %s" % (trailname, response))
    
    return response


# Send notification via SNS
def notify_admin(topic, description):
    snsclient = boto3.client('sns')
    response = snsclient.publish(
        TargetArn = topic,
        Message = "Event description: \"%s\" " %description,
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
    logger.setLevel(logging.INFO)

    # log the start of the remediation response
    logger.info("Starting automatic CloudTrail remediation response")

    # extract trail ARN by parsing the incoming CloudTrail event (in JSON format)
    trailARN = event['detail']['requestParameters']['name']
    
    # description contains useful details to be sent to security operations
    description = event['detail']

    # If debug logging set, write out details to logs for better audit path
    logger.debug("Event is-- %s" %event)
    logger.debug("trailARN is--- %s" %trailARN)
    logger.debug("snsARN is-- %s" %snsARN)
       
    # Enabling the AWS CloudTrail logging
    try:
        response = get_cloudtrail_status(trailARN)
        if response == False:
            response = enable_cloudtrail(trailARN)
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                message = "CloudTrail logging restarted automatically for trail - " + trailARN + "\n \n Event:" + str(description) + "\n \n Response:" + str(response) + "."
                notify_admin(snsARN, message)
                logger.info("Completed automatic CloudTrail remediation response for %s - %s" % (trailARN, response))
        elif response == True:
            logger.info("CloudTrail logging is already enabled for %s. Exiting" %trailARN)
        else:
            logger.error("Something went wrong - %s, %s" % (trailARN, event))

    except ClientError as e:
        logger.error("An error occured: %s" %e)