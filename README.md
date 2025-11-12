# AWS SNS Webhook Receiver to send notifications to Slack

[![Python Version: 3.12](
https://img.shields.io/badge/Python%20application-v3.12-blue
)](https://www.python.org/downloads/release/python-3123/)
[![License: GPL 3.0](
https://img.shields.io/github/license/ashleykleynhans/sns-webhook-slack
)](https://opensource.org/licenses/GPL-3.0)

## Prerequisites

1. Install [ngrok](https://ngrok.com/).
```bash
brew install ngrok
```
2. Ensure your System Python3 version is 3.12.
```bash
python3 -V
```
3. If your System Python is not 3.12:
```bash
brew install python@3.12
brew link python@3.12
```
4. [Create a new Slack App](https://api.slack.com/start).
5. Create your Slack channel where you want to receive your SNS notifications.
6. Configure SNS to send notifications to that channel.
7. Create a configuration file called `config.yml` in the same directory
   as the webhook script that looks like this:
```yml
---
slack:
  token: "<SLACK_TOKEN>"
  channels:
     default:
        us-east-1: aws-alerts-prod
        us-east-2: aws-alerts-test
     autoscaling:
        us-east-1: aws-autoscaling-prod
        us-east-2: aws-autoscaling-test
     health:
        us-east-1: aws-health-prod
        us-east-2: aws-health-test
     acm:
        us-east-1: aws-security-prod
        us-east-2: aws-security-test
     rekognition:
        us-east-1: aws-alerts-prod
        us-east-2: aws-alerts-test
     security-hub:
        us-east-1: aws-security-prod
        us-east-2: aws-security-test
     trusted-advisor:
        us-east-1: aws-alerts-prod
        us-east-2: aws-alerts-test
     config:
        us-east-1: aws-compliance-prod
        us-east-2: aws-compliance-test
     cloudwatch:
        us-east-1: aws-alerts-prod
        us-east-2: aws-alerts-test
     aws-service:
        us-east-1: aws-alerts-prod
        us-east-2: aws-alerts-test
     support:
        us-east-1: aws-support-prod
        us-east-2: aws-support-test
     savings-plans:
        us-east-1: aws-billing-prod
        us-east-2: aws-billing-test

influxdb:
   prod:
      url: http://prod-influxdb.example.com:8086
      token: "<INFLUXDB_TOKEN>"
      org: YourOrg
      bucket: BucketName
   test:
      url: http://test-influxdb.example.com:8086
      token: "<INFLUXDB_TOKEN>"
      org: YourOrg
      bucket: BucketName

environments:
   us-east-1: prod
   us-east-2: test
```

## Supported Notification Types

The webhook now supports the following AWS notification types with custom formatting:

- **`default`**: Regular AWS notifications (fallback for unrecognized types)
- **`autoscaling`**: EC2 Auto Scaling events (launch, terminate, etc.)
- **`health`**: AWS Health Dashboard events
- **`acm`**: ACM Certificate notifications (expiring, renewal status)
- **`rekognition`**: Amazon Rekognition notifications (EOL, deprecation)
- **`security-hub`**: AWS Security Hub findings
- **`trusted-advisor`**: AWS Trusted Advisor check results
- **`config`**: AWS Config compliance change notifications
- **`cloudwatch`**: CloudWatch Alarm state changes
- **`aws-service`**: Generic AWS service events from EventBridge
- **`support`**: AWS Support case updates
- **`savings-plans`**: AWS Savings Plans alerts

Each notification type can be routed to different Slack channels per region. If a specific notification type or region is not configured, it will fall back to the `default` channel.

## AWS SNS Configuration

TODO

## Testing your Webhook

1. Run the webhook receiver from your terminal.
```bash
python3 webhook.py
```
2. Open a new terminal window and use [ngrok](https://ngrok.com/) to create
a URL that is publically accessible through the internet by creating a tunnel
to the webhook receiver that is running on your local machine.
```bash
ngrok http 8090
```
3. Note that the ngrok URL will change if you stop ngrok and run it again,
   so keep it running in a separate terminal window, otherwise you will not
   be able to test your webhook successfully.
4. Update your SNS webhook configuration to the URL that is displayed
while ngrok is running **(be sure to use the https one)**.
5. Trigger an SNS event to trigger the notification webhook.
6. Check your Slack channel that you created for your SNS notifications.

## Deploy to AWS Lambda

1. Create a Python 3.12 Virtual Environment:
```bash
python3 -m venv venv/py3.12
source venv/py3.12/bin/activate
```
2. Upgrade pip.
```bash
python3 -m pip install --upgrade pip
```
3. Install the Python dependencies that are required by the Webhook receiver:
```bash
pip3 install -r requirements.txt
```
4. Create a file called `zappa_settings.json` and insert the JSON content below
to configure your AWS Lambda deployment:
```json
{
    "sns": {
        "app_function": "webhook.app",
        "aws_region": "us-east-1",
        "lambda_description": "Webhook to handle SNS notifications",
        "profile_name": "default",
        "project_name": "sns-webhook",
        "runtime": "python3.12",
        "s3_bucket": "sns-webhooks",
        "tags": {
            "service": "sns-webhook"
        }
    }
}
```
5. Use [Zappa](https://github.com/Zappa/Zappa) to deploy your Webhook
to AWS Lambda (this is installed as part of the dependencies above):
```bash
zappa deploy
```
6. Take note of the URL that is returned by the `zappa deploy` command,
eg. `https://1d602d00.execute-api.us-east-1.amazonaws.com/sns`
   (obviously use your own and don't copy and paste this one, or your
Webhook will not work).

**NOTE:** If you get the following error when running the `zappa deploy` command:

<pre>
botocore.exceptions.ClientError:
An error occurred (IllegalLocationConstraintException) when calling
the CreateBucket operation: The unspecified location constraint
is incompatible for the region specific endpoint this request was sent to.
</pre>

This error usually means that your S3 bucket name is not unique, and that you
should change it to something different, since the S3 bucket names are not
namespaced and are global for everyone.

7. Check the status of the API Gateway URL that was created by zappa:
```bash
zappa status
```
8. Test your webhook by making a curl request to the URL that was returned
by `zappa deploy`:
```
curl https://1d602d00.execute-api.us-east-1.amazonaws.com/sns
```
You should expect the following response:
```json
{"status":"ok"}
```
9. Update your Webhook URL in SNS to the one returned by the
`zappa deploy` command.
10. You can view your logs by running:
```bash
zappa tail
```
