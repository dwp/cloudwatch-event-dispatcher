import sys
import argparse
import boto3
import logging
import os
import json

# Initialise logging
logger = logging.getLogger(__name__)
log_level = os.environ["LOG_LEVEL"] if "LOG_LEVEL" in os.environ else "ERROR"
logger.setLevel(logging.getLevelName(log_level.upper()))
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(module)s "
    "%(process)s[%(thread)s] %(message)s",
)
logger.info("Logging at {} level".format(log_level.upper()))


def get_parameters():
    parser = argparse.ArgumentParser(
        description="Receive CloudWatch events and post to SNS with additional message attributes"
    )

    # Parse command line inputs and set defaults
    parser.add_argument("--aws-profile", default="default")
    parser.add_argument("--aws-region", default="eu-west-2")
    parser.add_argument("--sns-topic-arn", default="")

    _args = parser.parse_args()

    # Override arguments with environment variables where set
    if "AWS_PROFILE" in os.environ:
        _args.aws_profile = os.environ["AWS_PROFILE"]

    if "AWS_REGION" in os.environ:
        _args.aws_region = os.environ["AWS_REGION"]

    if "SNS_TOPIC_ARN" in os.environ:
        _args.sns_topic_arn = os.environ["SNS_TOPIC_ARN"]

    return _args


def handler(event, context):
    args = get_parameters()
    try:
        cloudwatch_event_dispatcher(event, args)
    except KeyError as key_name:
        logger.error(f"Key: {key_name} is required in payload")


def cloudwatch_event_dispatcher(event, args):
    if "AWS_PROFILE" in os.environ:
        boto3.setup_default_session(
            profile_name=args.aws_profile, region_name=args.aws_region
        )

    if logger.isEnabledFor(logging.DEBUG):
        # Log everything from boto3
        boto3.set_stream_logger()
        logger.debug(f"Using boto3 {boto3.__version__}")

    message_attributes = {
        "account": {"StringValue": event["account"], "DataType": "String"},
        "region": {"StringValue": event["region"], "DataType": "String"},
        "source": {"StringValue": event["source"], "DataType": "String"},
        "detailType": {"StringValue": event["detail-type"], "DataType": "String"},
    }

    # Add attributes specific to ECS Task state changes
    if event["source"] == "aws.ecs" and event["detail-type"] == "ECS Task State Change":
        message_attributes["clusterArn"] = {
            "StringValue": event["detail"]["clusterArn"],
            "DataType": "String",
        }
        message_attributes["clusterService"] = {
            "StringValue": event["detail"]["group"].replace("service:", ""),
            "DataType": "String",
        }
        message_attributes["lastStatus"] = {
            "StringValue": event["detail"]["containers"][0]["lastStatus"],
            "DataType": "String",
        }
        message_attributes["desiredStatus"] = {
            "StringValue": event["detail"]["desiredStatus"],
            "DataType": "String",
        }

    if send_sns_notification(event, message_attributes, args.sns_topic_arn):
        logger.info("Message successfully dispatched")


def send_sns_notification(event, message_attributes, sns_topic_arn):

    sns_client = boto3.client("sns")
    response = sns_client.publish(
        TargetArn=sns_topic_arn,
        Message=json.dumps(event),
        MessageStructure="string",
        MessageAttributes=message_attributes,
    )
    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        logger.error("Bad response from SNS client when publishing message")
        logger.error(response)
        return False
    logger.info(response)
    return True


if __name__ == "__main__":
    try:
        json_content = json.loads(open("event.json", "r").read())
        handler(json_content, None)
    except Exception as e:
        logger.error("Unexpected error occurred")
        logger.error(e)
        raise e
