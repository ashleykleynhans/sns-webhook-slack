#!/usr/bin/env python3
import json
import sys
import argparse
import yaml
import requests
import re
from flask import Flask, request, jsonify, make_response
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

NOTIFICATION_TYPE_DEFAULT = 'default'
NOTIFICATION_TYPE_HEALTH = 'health'
NOTIFICATION_TYPE_AUTOSCALING = 'autoscaling'

COLORS = {
    'autoscaling:EC2_INSTANCE_LAUNCH': 'good',
    'autoscaling:EC2_INSTANCE_TERMINATE': 'danger',
    'autoscaling:EC2_INSTANCE_TERMINATE_ERROR': 'danger',
    'autoscaling:EC2_INSTANCE_LAUNCH_ERROR': 'danger',
}

EXCLUDE = [
    'autoscaling:TEST_NOTIFICATION'
]


def get_args():
    parser = argparse.ArgumentParser(
        description='AWS SNS Webhook Receiver to Send Slack Notifications'
    )

    parser.add_argument(
        '-p', '--port',
        help='Port to listen on',
        type=int,
        default=8090
    )

    parser.add_argument(
        '-H', '--host',
        help='Host to bind to',
        default='0.0.0.0'
    )

    return parser.parse_args()


def load_config():
    try:
        config_file = 'config.yml'

        with open(config_file, 'r') as stream:
            return yaml.safe_load(stream)
    except FileNotFoundError:
        print(f'ERROR: Config file {config_file} not found!')
        sys.exit()


config = load_config()

if 'slack' not in config:
    print("'slack' section not found in config")
    sys.exit(1)

if 'token' not in config['slack']:
    print("'token' not found in 'slack' section of config")
    sys.exit(1)

if 'channels' not in config['slack']:
    print("'channels' not found in 'slack' section of config")
    sys.exit(1)

if 'url' in config['slack']:
    slack_url = config['slack']['url'] + '/' + config['slack']['token']
else:
    slack_url = 'https://slack.com/api/chat.postMessage'

slack_token = config['slack']['token']
slack_channels = config['slack']['channels']
app = Flask(__name__)


def influxdb_log(message):
    try:
        if 'influxdb' not in config:
            return

        match = re.search(r'^([a-z]+-[a-z]+-\d+)', message['AvailabilityZone'])

        if match:
            region = match.group(1)
        else:
            return

        if region in config['environments']:
            count_before = 0
            count_after = 0

            increasing_matches = re.findall(r'increasing the capacity from (\d+) to (\d+)', message['Cause'])

            if increasing_matches:
                count_before = increasing_matches[0][0]
                count_after = increasing_matches[0][1]
            else:
                decreasing_matches = re.findall(r'shrinking the capacity from (\d+) to (\d+)', message['Cause'])

                if decreasing_matches:
                    count_before = decreasing_matches[0][0]
                    count_after = decreasing_matches[0][1]

            if count_before == 0 and count_after == 0:
                return

            asg = message['AutoScalingGroupName'].split('-')
            application = asg[0]

            environment = config['environments'][region]
            influxdb_config = config['influxdb'][environment]

            print('Logging to InfluxDB')

            client = InfluxDBClient(
                url=influxdb_config['url'],
                token=influxdb_config['token'],
                org=influxdb_config['org']
            )

            point = Point('ec2_autoscaling') \
                .tag('application', application) \
                .field('availability_zone', message['AvailabilityZone']) \
                .field('autoscaling_group', message['AutoScalingGroupName']) \
                .field('count_before', int(count_before)) \
                .field('count_after', int(count_after))

            write_api = client.write_api(write_options=SYNCHRONOUS)
            write_api.write(
                influxdb_config['bucket'],
                influxdb_config['org'],
                point,
                write_precision=WritePrecision.S
            )

            client.close()
    except Exception as e:
        print(f'Logging to InfluxDB failed: {e}')


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify(
        {
            'status': 'error',
            'msg': f'{request.url} not found',
            'detail': str(error)
        }
    ), 404)


@app.errorhandler(500)
def internal_server_error(error):
    return make_response(jsonify(
        {
            'status': 'error',
            'msg': 'Internal Server Error',
            'detail': str(error)
        }
    ), 500)


@app.route('/', methods=['GET'])
def ping():
    return make_response(jsonify(
        {
            'status': 'ok'
        }
    ), 200)


@app.route(f'/', methods=['POST'])
def webhook_handler():
    try:
        color = 'good'
        message = ''
        sns_payload = json.loads(request.data.decode('utf-8'))
        notification_type = NOTIFICATION_TYPE_DEFAULT

        try:
            sns_message = sns_payload['Message']
            sns_message = json.loads(sns_message)

            if 'Event' in sns_message and sns_message['Event'] in COLORS:
                color = COLORS[sns_message['Event']]

                if 'autoscaling:' in sns_message['Event']:
                    notification_type = NOTIFICATION_TYPE_AUTOSCALING
            elif 'detail-type' in sns_message and sns_message['detail-type'] == 'AWS Health Event':
                notification_type = NOTIFICATION_TYPE_HEALTH

                if sns_message['detail']['eventTypeCategory'] == 'issue':
                    color = 'danger'

            if notification_type == NOTIFICATION_TYPE_HEALTH:
                message += f'**Account:** {sns_message["account"]}\n'
                message += f'**Region:** {sns_message["region"]}\n'

                if sns_message["resources"]:
                    message += f'**Resources:** {",".join(sns_message["resources"])}\n'

                message += f'**Service:** {sns_message["detail"]["service"]}\n'
                message += f'**Event Type Code:** {sns_message["detail"]["eventTypeCode"]}\n'
                message += f'**Event Type Category:** {sns_message["detail"]["eventTypeCategory"]}\n'
                message += f'**Start Time:** {sns_message["detail"]["startTime"]}\n'
                message += f'**End Time:** {sns_message["detail"]["endTime"]}\n'
                message += '**Description:**\n'

                for description_item in sns_message['detail']['eventDescription']:
                    if description_item['language'] == 'en_US':
                        message += description_item['latestDescription'] + '\n'

                    if 'affectedEntities' in sns_message['detail']:
                        message += '**Affected Entities:**\n'

                        for affected_enttity in sns_message['detail']['affectedEntities']:
                            message += f'  * {affected_enttity["entityValue"]}\n'
            elif notification_type == NOTIFICATION_TYPE_AUTOSCALING:
                sns_message['AvailabilityZone'] = sns_message['Details']['Availability Zone']
                del sns_message['Details']

                for msg_item in sns_message.keys():
                    message += f'**{msg_item}:** {sns_message[msg_item]}\n'

                if sns_message['Event'] == 'autoscaling:EC2_INSTANCE_LAUNCH' or sns_message['Event'] == 'autoscaling:EC2_INSTANCE_TERMINATE':
                    influxdb_log(sns_message)
            else:
                for msg_item in sns_message.keys():
                    message += f'{msg_item}: {sns_message[msg_item]}\n'
        except Exception as e:
            # Not a JSON message
            message = sns_payload['Message']

        if 'SubscribeURL' in sns_payload:
            message += f"\n\nSubscribeURL: {sns_payload['SubscribeURL']}"

        # Don't send Slack notifications for excluded SNS event types
        if 'Event' in sns_message and sns_message['Event'] in EXCLUDE:
            return make_response(jsonify(
                {
                    'status': 'ok'
                }
            ), 200)

        arn = sns_payload['TopicArn'].split(':')
        region = arn[3]

        if notification_type not in slack_channels:
            raise Exception(f'{notification_type} notification type not found within the "slack" section of the config file')

        if region not in slack_channels[notification_type]:
            raise Exception(f'{region} not found within the {notification_type} slack configuration')

        slack_channel = slack_channels[notification_type][region]

        slack_payload = {
            'attachments': [
                {
                    'text': message,
                    'fallback': message,
                    'color': color
                }
            ],
            'channel': f'#{slack_channel}'
        }

        if 'Subject' in sns_payload:
            slack_payload['attachments'][0]['title'] = sns_payload['Subject']
        elif 'detail-type' in sns_message:
            slack_payload['attachments'][0]['title'] = sns_message['detail-type']

        response = requests.post(
            url=slack_url,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {slack_token}'
            },
            json=slack_payload
        )

        slack_response = response.json()

        if response.status_code != 200:
            return make_response(jsonify(
                {
                    'status': 'error',
                    'msg': 'Failed to send Slack notification',
                    'detail': slack_response
                }
            ), 500)

        return jsonify(slack_response)
    except Exception as e:
        return make_response(jsonify(
            {
                'status': 'error',
                'msg': 'Error',
                'detail': str(e)
            }
        ), 500)


if __name__ == '__main__':
    args = get_args()

    app.run(
        host=args.host,
        port=args.port
    )
