#!/usr/bin/env python3
import json
import sys
import argparse
import yaml
import requests
from flask import Flask, request, jsonify, make_response
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

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

if 'url' in config['slack']:
    slack_url = config['slack']['url'] + '/' + config['slack']['token']
else:
    slack_url = 'https://slack.com/api/chat.postMessage'

slack_token = config['slack']['token']
slack_channel = config['slack']['channel']
app = Flask(__name__)


def influxdb_log(message):
    try:
        if message['Event'] == 'autoscaling:EC2_INSTANCE_TERMINATE' \
                and 'taken out of service in response to an EC2 health check' in message['Cause']:
            print('Logging to InfluxDB')
            asg_name = message['AutoScalingGroupName']
            asg_name = asg_name.split('-')
            asg_name.pop()
            asg_name = ('-').join(asg_name)

            if 'test' in asg_name:
                influxdb_config = config['influxdb']['test']
            else:
                influxdb_config = config['influxdb']['prod']

            client = InfluxDBClient(
                url=influxdb_config['url'],
                token=influxdb_config['token'],
                org=influxdb_config['org']
            )

            point = Point('spot_termination') \
                .tag('availability_zone', message['Details']['Availability Zone']) \
                .tag('autoscaling_group', asg_name) \
                .field('count', 1)

            write_api = client.write_api(write_options=SYNCHRONOUS)
            write_api.write(
                config['influxdb']['bucket'],
                config['influxdb']['org'],
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
    #sns_headers = dict(request.headers)
    color = 'good'
    message = ''
    sns_payload = json.loads(request.data.decode('utf-8'))

    try:
        sns_message = json.loads(sns_payload['Message'])

        for msg_item in sns_message.keys():
            message += f'{msg_item}: {sns_message[msg_item]}\n'

        if sns_message['Event'] in COLORS:
            color = COLORS[sns_message['Event']]
    except Exception as e:
        # Not a JSON message
        message = sns_payload['Message']

    if 'SubscribeURL' in sns_payload:
        message += f"\n\nSubscribeURL: {sns_payload['SubscribeURL']}"

    # Don't send Slack notifications for excluded SNS event types
    if sns_message['Event'] in EXCLUDE:
        return make_response(jsonify(
            {
                'status': 'ok'
            }
        ), 200)

    influxdb_log(sns_message)

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


if __name__ == '__main__':
    args = get_args()

    app.run(
        host=args.host,
        port=args.port
    )
