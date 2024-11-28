#!/usr/bin/env python3
"""
AWS SNS Webhook Receiver for Slack Notifications.

This service receives AWS SNS notifications and forwards them to Slack channels.
It supports various notification types including health checks, autoscaling events,
support cases, and savings plans alerts.
"""

from typing import Dict, Any, Optional, TypedDict
import json
import sys
import argparse
import yaml
import requests
import re
from dataclasses import dataclass
from flask import Flask, request, jsonify, make_response, Response
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS


# Type definitions
class SlackConfig(TypedDict):
    """Type definition for Slack configuration."""
    token: str
    channels: Dict[str, Dict[str, str]]
    url: Optional[str]


class Config(TypedDict):
    """Type definition for application configuration."""
    slack: SlackConfig
    influxdb: Optional[Dict[str, Dict[str, str]]]
    environments: Optional[Dict[str, str]]


@dataclass
class NotificationTypes:
    """Constants for notification types."""
    DEFAULT: str = 'default'
    HEALTH: str = 'health'
    AUTOSCALING: str = 'autoscaling'
    SUPPORT: str = 'support'
    SAVINGS_PLANS: str = 'savings-plans'


# Constants
NOTIFICATION_TYPES = NotificationTypes()

COLORS: Dict[str, str] = {
    'autoscaling:EC2_INSTANCE_LAUNCH': 'good',
    'autoscaling:EC2_INSTANCE_TERMINATE': 'danger',
    'autoscaling:EC2_INSTANCE_TERMINATE_ERROR': 'danger',
    'autoscaling:EC2_INSTANCE_LAUNCH_ERROR': 'danger',
}

EXCLUDE: list[str] = [
    'autoscaling:TEST_NOTIFICATION'
]


def get_args() -> argparse.Namespace:
    """
    Parse and return command line arguments.

    Returns:
        argparse.Namespace: Parsed command line arguments
    """
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


def load_config() -> Config:
    """
    Load and validate configuration from config.yml file.

    Returns:
        Config: Parsed configuration dictionary

    Raises:
        SystemExit: If config file is missing or invalid
    """
    try:
        config_file = 'config.yml'
        with open(config_file, 'r') as stream:
            config: Config = yaml.safe_load(stream)

        validate_config(config)
        return config
    except FileNotFoundError:
        print(f'ERROR: Config file {config_file} not found!')
        sys.exit(1)


def validate_config(config: Config) -> None:
    """
    Validate the configuration structure.

    Args:
        config: Configuration dictionary to validate

    Raises:
        SystemExit: If configuration is invalid
    """
    if 'slack' not in config:
        print("'slack' section not found in config")
        sys.exit(1)

    if 'token' not in config['slack']:
        print("'token' not found in 'slack' section of config")
        sys.exit(1)

    if 'channels' not in config['slack']:
        print("'channels' not found in 'slack' section of config")
        sys.exit(1)


def _parse_sns_message(sns_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse the SNS message from the payload.

    Args:
        sns_payload: Raw SNS payload

    Returns:
        Optional[Dict[str, Any]]: Parsed SNS message or None if parsing fails
    """
    try:
        sns_message = sns_payload['Message']
        return json.loads(sns_message)
    except (KeyError, json.JSONDecodeError):
        # Not a JSON message or no Message field
        return None


def _determine_notification_type(sns_message: Dict[str, Any]) -> tuple[str, str]:
    """
    Determine the notification type and color from the SNS message.

    Args:
        sns_message: Parsed SNS message

    Returns:
        tuple[str, str]: Notification type and color
    """
    color = 'good'
    notification_type = NOTIFICATION_TYPES.DEFAULT

    if 'Event' in sns_message and sns_message['Event'] in COLORS:
        color = COLORS[sns_message['Event']]
        if 'autoscaling:' in sns_message['Event']:
            notification_type = NOTIFICATION_TYPES.AUTOSCALING
    elif 'detail-type' in sns_message:
        if sns_message['detail-type'] == 'Support Case Update':
            notification_type = NOTIFICATION_TYPES.SUPPORT
        elif sns_message['detail-type'] == 'Savings Plans State Change Alert':
            notification_type = NOTIFICATION_TYPES.SAVINGS_PLANS
        elif sns_message['detail-type'] == 'AWS Health Event':
            notification_type = NOTIFICATION_TYPES.HEALTH
            if sns_message['detail']['eventTypeCategory'] == 'issue':
                color = 'danger'

    return notification_type, color


def _format_message(sns_message: Dict[str, Any], notification_type: str) -> str:
    """
    Format the message based on notification type.

    Args:
        sns_message: Parsed SNS message
        notification_type: Type of notification

    Returns:
        str: Formatted message
    """
    message = ''

    if notification_type == NOTIFICATION_TYPES.HEALTH:
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
            for affected_entity in sns_message['detail']['affectedEntities']:
                message += f'  * {affected_entity["entityValue"]}\n'

    elif notification_type == NOTIFICATION_TYPES.AUTOSCALING:
        sns_message['AvailabilityZone'] = sns_message['Details']['Availability Zone']
        del sns_message['Details']

        for msg_item in sns_message.keys():
            message += f'**{msg_item}:** {sns_message[msg_item]}\n'

    else:
        for msg_item in sns_message.keys():
            message += f'{msg_item}: {sns_message[msg_item]}\n'

    return message


def _should_skip_notification(sns_message: Dict[str, Any]) -> bool:
    """
    Determine if the notification should be skipped.

    Args:
        sns_message: Parsed SNS message

    Returns:
        bool: True if notification should be skipped
    """
    return 'Event' in sns_message and sns_message['Event'] in EXCLUDE


def _get_slack_channel(config: Config, notification_type: str, region: str) -> str:
    """
    Get the appropriate Slack channel for the notification.

    Args:
        config: Application configuration
        notification_type: Type of notification
        region: AWS region

    Returns:
        str: Slack channel name

    Raises:
        Exception: If channel configuration is invalid
    """
    if notification_type not in config['slack']['channels']:
        raise Exception(
            f'{notification_type} notification type not found within the "slack" section of the config file'
        )

    if region not in config['slack']['channels'][notification_type]:
        raise Exception(
            f'{region} not found within the {notification_type} slack configuration'
        )

    return config['slack']['channels'][notification_type][region]


class InfluxDBLogger:
    """Handle logging of autoscaling events to InfluxDB."""

    def __init__(self, config: Config):
        """Initialize InfluxDB logger with configuration."""
        self.config = config

    def log_autoscaling_event(self, message: Dict[str, Any]) -> None:
        """
        Log autoscaling event to InfluxDB.

        Args:
            message: Autoscaling event message to log
        """
        try:
            if 'influxdb' not in self.config:
                return

            region = self._extract_region(message.get('AvailabilityZone', ''))
            if not region:
                return

            if region not in self.config.get('environments', {}):
                return

            count_before, count_after = self._extract_capacity_changes(message.get('Cause', ''))
            if count_before == 0 and count_after == 0:
                return

            self._write_to_influxdb(message, region, count_before, count_after)

        except Exception as e:
            print(f'Logging to InfluxDB failed: {e}')

    def _extract_region(self, availability_zone: str) -> Optional[str]:
        """Extract region from availability zone."""
        match = re.search(r'^([a-z]+-[a-z]+-\d+)', availability_zone)
        return match.group(1) if match else None

    def _extract_capacity_changes(self, cause: str) -> tuple[int, int]:
        """Extract capacity changes from cause message."""
        increasing_matches = re.findall(r'increasing the capacity from (\d+) to (\d+)', cause)
        if increasing_matches:
            return int(increasing_matches[0][0]), int(increasing_matches[0][1])

        decreasing_matches = re.findall(r'shrinking the capacity from (\d+) to (\d+)', cause)
        if decreasing_matches:
            return int(decreasing_matches[0][0]), int(decreasing_matches[0][1])

        return 0, 0

    def _write_to_influxdb(self, message: Dict[str, Any], region: str, count_before: int, count_after: int) -> None:
        """Write event data to InfluxDB."""
        environment = self.config['environments'][region]
        influxdb_config = self.config['influxdb'][environment]

        asg = message['AutoScalingGroupName'].split('-')
        application = asg[0]

        client = InfluxDBClient(
            url=influxdb_config['url'],
            token=influxdb_config['token'],
            org=influxdb_config['org']
        )

        try:
            point = Point('ec2_autoscaling') \
                .tag('application', application) \
                .field('availability_zone', message['AvailabilityZone']) \
                .field('autoscaling_group', message['AutoScalingGroupName']) \
                .field('count_before', count_before) \
                .field('count_after', count_after)

            write_api = client.write_api(write_options=SYNCHRONOUS)
            write_api.write(
                influxdb_config['bucket'],
                influxdb_config['org'],
                point,
                write_precision=WritePrecision.S
            )
        finally:
            client.close()


class SlackNotifier:
    """Handle sending notifications to Slack."""

    def __init__(self, config: Config):
        """Initialize Slack notifier with configuration."""
        self.config = config
        self.slack_url = (
            f"{config['slack']['url']}/{config['slack']['token']}"
            if 'url' in config['slack']
            else 'https://slack.com/api/chat.postMessage'
        )
        self.slack_token = config['slack']['token']

    def send_notification(self, message: str, channel: str, color: str = 'good', title: Optional[str] = None) -> Dict[str, Any]:
        """
        Send notification to Slack.

        Args:
            message: Message content
            channel: Target Slack channel
            color: Message color/severity indicator
            title: Optional message title

        Returns:
            Dict[str, Any]: Slack API response

        Raises:
            Exception: If Slack notification fails
        """
        slack_payload = {
            'attachments': [
                {
                    'text': message,
                    'fallback': message,
                    'color': color
                }
            ],
            'channel': f'#{channel}'
        }

        if title:
            slack_payload['attachments'][0]['title'] = title

        response = requests.post(
            url=self.slack_url,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.slack_token}'
            },
            json=slack_payload
        )

        if response.status_code != 200:
            raise Exception(f'Slack API error: {response.json()}')

        return response.json()


def create_app(config: Config) -> Flask:
    """
    Create and configure Flask application.

    Args:
        config: Application configuration

    Returns:
        Flask: Configured Flask application
    """
    app = Flask(__name__)
    influxdb_logger = InfluxDBLogger(config)
    slack_notifier = SlackNotifier(config)

    @app.errorhandler(404)
    def not_found(error: Exception) -> Response:
        """Handle 404 errors."""
        return make_response(jsonify({
            'status': 'error',
            'msg': f'{request.url} not found',
            'detail': str(error)
        }), 404)

    @app.errorhandler(500)
    def internal_server_error(error: Exception) -> Response:
        """Handle 500 errors."""
        return make_response(jsonify({
            'status': 'error',
            'msg': 'Internal Server Error',
            'detail': str(error)
        }), 500)

    @app.route('/', methods=['GET'])
    def ping() -> Response:
        """Health check endpoint."""
        return make_response(jsonify({'status': 'ok'}), 200)

    @app.route('/', methods=['POST'])
    def webhook_handler() -> Response:
        """
        Handle incoming SNS webhook notifications.

        Returns:
            Response: JSON response indicating success or failure
        """
        try:
            sns_payload = json.loads(request.data.decode('utf-8'))
            notification_type = NOTIFICATION_TYPES.DEFAULT
            color = 'good'
            message = ''

            sns_message = _parse_sns_message(sns_payload)
            if not sns_message:
                return make_response(jsonify({'status': 'ok'}), 200)

            notification_type, color = _determine_notification_type(sns_message)
            message = _format_message(sns_message, notification_type)

            if _should_skip_notification(sns_message):
                return make_response(jsonify({'status': 'ok'}), 200)

            # Log to InfluxDB if applicable
            if notification_type == NOTIFICATION_TYPES.AUTOSCALING:
                influxdb_logger.log_autoscaling_event(sns_message)

            # Send to Slack
            region = sns_payload['TopicArn'].split(':')[3]
            channel = _get_slack_channel(config, notification_type, region)

            title = sns_payload.get('Subject') or sns_message.get('detail-type')
            slack_response = slack_notifier.send_notification(message, channel, color, title)

            return jsonify(slack_response)

        except Exception as e:
            return make_response(jsonify({
                'status': 'error',
                'msg': 'Error',
                'detail': str(e)
            }), 500)

    return app


# Create the Flask app at module level to support AWS Lambda
# Don't move this into main() function.
config = load_config()
app = create_app(config)


def main() -> None:
    """Main application entry point."""
    args = get_args()
    app.run(
        host=args.host,
        port=args.port
    )


if __name__ == '__main__':
    main()
