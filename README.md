# cloudwatch-event-dispatcher
Lambda to receive CloudWatch events and post to SNS with additional message attributes

### Envirnonment Variables
The following variables can be passed in to the lambda call as overrides:
AWS_PROFILE - the aws profile to use (set up in `.aws/config` - usually for local development)
AWS_REGION - the aws region to use
SNS_TOPIC_ARN - the ARN of the SNS topic to point at

### Functionality
The lambda takes in [an AWS event](https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/WhatIsCloudWatchEvents.html) as a trigger and creates a JSON schema of important attributes and publishes it to SNS alongside the event itself. 

the JSON schema will follow this pattern:
```
{
    "account": {"StringValue": <ACCOUNT>, "DataType": "String"},
    "region": {"StringValue": <REGION>, "DataType": "String"},
    "source": {"StringValue": <SOURCE>, "DataType": "String"},
    "detailType": {"StringValue": <DETAIL_TYPE>, "DataType": "String"},
}
```

Unless the even source is ECS, where the addition of `clusterArn`, `clusterService`, `lastStatus` and `desiredStatus` attributes will be included.
