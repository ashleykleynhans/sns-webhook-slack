#!/usr/bin/env python3
import json
import sys
import argparse
import yaml
import requests
from flask import Flask, request, jsonify, make_response


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


def send_slack_notification():
    sns_headers = request.headers
    sns_payload = request.get_json()

    print(json.dumps(sns_headers, indent=4))
    print(json.dumps(sns_payload, indent=4))

    return make_response(jsonify(
        {
            'status': 'ok'
        }
    ), 200)
    message = ''
    #
    # slack_payload = {
    #     'attachments': [
    #         {
    #             'title':
    #             'fallback': message,
    #             'color': 'danger'
    #         }
    #     ]
    # }
    #
    # return requests.post(
    #     url=slack_url,
    #     headers={
    #         'Content-Type': 'application/json',
    #         'Authorization': f'Bearer {slack_token}'
    #     },
    #     json=slack_payload
    # )


config = load_config()

if 'slack' not in config:
    print("'slack' section not found in config")
    sys.exit(1)

if 'token' not in config['slack']:
    print("'token' not found in 'slack' section of config")
    sys.exit(1)

if 'url' in config['slack']:
    slack_url = config['slack']['url']
else:
    slack_url = 'https://slack.com/api/chat.postMessage'

slack_token = config['slack']['token']
app = Flask(__name__)


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
    response = send_slack_notification()
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
