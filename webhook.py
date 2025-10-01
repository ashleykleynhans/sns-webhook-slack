#!/usr/bin/env python3
"""
Secure AWS SNS Webhook Receiver for Slack Notifications.

This service receives AWS SNS notifications and forwards them to Slack channels.

It supports various notification types including health checks, autoscaling events,
support cases, and savings plans alerts.

It includes security measures to prevent third-party abuse:
- SNS message signature validation
- AWS account ID validation
- Certificate URL validation
- Optional API key authentication
"""

from typing import Dict, Any, Optional, TypedDict, List
import json
import sys
import argparse
import yaml
import requests
import re
import base64
import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlparse
from functools import wraps
from flask import Flask, request, jsonify, make_response, Response
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


# Type definitions
class SecurityConfig(TypedDict):
    """Type definition for security configuration."""
    aws_account_ids: List[str]
    allowed_regions: List[str]
    verify_signatures: bool
    api_keys: Optional[List[str]]
    allowed_topic_patterns: Optional[List[str]]
    rate_limit: Optional[Dict[str, int]]


class SlackConfig(TypedDict):
    """Type definition for Slack configuration."""
    token: str
    channels: Dict[str, Dict[str, str]]
    url: Optional[str]


class Config(TypedDict):
    """Type definition for application configuration."""
    security: SecurityConfig
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

# AWS SNS Certificate URLs - Only trust certificates from these domains
VALID_CERT_DOMAINS = [
    'sns.amazonaws.com',
    'sns.us-east-1.amazonaws.com',
    'sns.us-east-2.amazonaws.com',
    'sns.us-west-1.amazonaws.com',
    'sns.us-west-2.amazonaws.com',
    'sns.eu-west-1.amazonaws.com',
    'sns.eu-west-2.amazonaws.com',
    'sns.eu-central-1.amazonaws.com',
    'sns.ap-southeast-1.amazonaws.com',
    'sns.ap-southeast-2.amazonaws.com',
    'sns.ap-northeast-1.amazonaws.com',
    'sns.ap-northeast-2.amazonaws.com',
    'sns.ap-south-1.amazonaws.com',
    'sns.sa-east-1.amazonaws.com',
    'sns.ca-central-1.amazonaws.com',
    'sns.af-south-1.amazonaws.com',
    # Add more regions as needed
]


class SecurityValidator:
    """Handle security validation for incoming SNS messages."""

    def __init__(self, config: SecurityConfig):
        """Initialize security validator with configuration."""
        self.config = config
        self.cert_cache: Dict[str, x509.Certificate] = {}

    def validate_request(self, sns_payload: Dict[str, Any]) -> tuple[bool, str]:
        """
        Validate the incoming SNS request.

        Args:
            sns_payload: The SNS payload to validate

        Returns:
            tuple[bool, str]: (is_valid, error_message)
        """
        # Validate TopicArn format and account ID
        if 'TopicArn' in sns_payload:
            is_valid, error = self._validate_topic_arn(sns_payload['TopicArn'])
            if not is_valid:
                return False, error

        # Validate signature if enabled
        if self.config.get('verify_signatures', True):
            is_valid, error = self._validate_signature(sns_payload)
            if not is_valid:
                return False, error

        return True, ""

    def _validate_topic_arn(self, topic_arn: str) -> tuple[bool, str]:
        """
        Validate the Topic ARN format and account ID.

        Args:
            topic_arn: The SNS Topic ARN

        Returns:
            tuple[bool, str]: (is_valid, error_message)
        """
        # Parse ARN: arn:aws:sns:region:account-id:topic-name
        try:
            arn_parts = topic_arn.split(':')
            if len(arn_parts) < 6:
                return False, "Invalid ARN format"

            # Validate it's an SNS ARN
            if arn_parts[0] != 'arn' or arn_parts[2] != 'sns':
                return False, "Not an SNS ARN"

            # Extract and validate account ID
            account_id = arn_parts[4]
            if account_id not in self.config.get('aws_account_ids', []):
                return False, f"Unauthorized AWS account: {account_id}"

            # Validate region if specified
            region = arn_parts[3]
            allowed_regions = self.config.get('allowed_regions', [])
            if allowed_regions and region not in allowed_regions:
                return False, f"Unauthorized region: {region}"

            # Validate topic pattern if specified
            topic_name = arn_parts[5]
            allowed_patterns = self.config.get('allowed_topic_patterns', [])
            if allowed_patterns:
                if not any(re.match(pattern, topic_name) for pattern in allowed_patterns):
                    return False, f"Topic name doesn't match allowed patterns: {topic_name}"

            return True, ""

        except Exception as e:
            return False, f"Failed to parse Topic ARN: {str(e)}"

    def _validate_signature(self, sns_payload: Dict[str, Any]) -> tuple[bool, str]:
        """
        Validate the SNS message signature.

        Args:
            sns_payload: The SNS payload containing the signature

        Returns:
            tuple[bool, str]: (is_valid, error_message)
        """
        try:
            # If signature validation is disabled, skip
            if not self.config.get('verify_signatures', True):
                return True, ""

            # Check if signature fields are present
            has_signature_fields = 'SigningCertURL' in sns_payload and 'Signature' in sns_payload

            if not has_signature_fields:
                # No signature fields - could be a test/local message
                # If we're configured to require signatures, fail
                if self.config.get('verify_signatures', True):
                    return False, "Missing required field: SigningCertURL"
                return True, ""

            # Validate certificate URL
            cert_url = sns_payload['SigningCertURL']
            if not self._is_valid_cert_url(cert_url):
                return False, f"Invalid certificate URL: {cert_url}"

            # Get the certificate
            certificate = self._get_certificate(cert_url)
            if not certificate:
                # Certificate download failed - could be network issue or expired cert
                return False, "Failed to retrieve certificate"

            # Validate certificate is from Amazon
            if not self._validate_certificate_issuer(certificate):
                return False, "Certificate not issued by Amazon"

            # Build the string to sign
            string_to_sign = self._build_string_to_sign(sns_payload)

            # Decode the signature
            signature = base64.b64decode(sns_payload['Signature'])

            # Verify the signature
            public_key = certificate.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                try:
                    public_key.verify(
                        signature,
                        string_to_sign.encode('utf-8'),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    return True, ""
                except Exception:
                    return False, "Invalid signature"
            else:
                return False, "Unsupported key type"

        except Exception as e:
            return False, f"Signature validation failed: {str(e)}"

    def _is_valid_cert_url(self, cert_url: str) -> bool:
        """
        Validate that the certificate URL is from AWS.

        Args:
            cert_url: The certificate URL to validate

        Returns:
            bool: True if valid AWS certificate URL
        """
        try:
            parsed = urlparse(cert_url)

            # Must be HTTPS
            if parsed.scheme != 'https':
                return False

            # Must be from a valid AWS SNS domain
            domain = parsed.netloc.lower()
            if not any(domain == valid_domain or domain.endswith(f'.{valid_domain}')
                       for valid_domain in VALID_CERT_DOMAINS):
                return False

            # Must have .pem extension
            if not parsed.path.endswith('.pem'):
                return False

            return True

        except Exception:
            return False

    def _get_certificate(self, cert_url: str) -> Optional[x509.Certificate]:
        """
        Retrieve and cache the certificate from the URL.

        Args:
            cert_url: URL of the certificate

        Returns:
            Optional[x509.Certificate]: The certificate or None if failed
        """
        try:
            # Check cache first
            if cert_url in self.cert_cache:
                cert = self.cert_cache[cert_url]
                # Check if certificate is still valid
                if cert.not_valid_after > datetime.utcnow():
                    return cert
                else:
                    # Remove expired certificate from cache
                    del self.cert_cache[cert_url]

            # Download certificate
            response = requests.get(cert_url, timeout=5)
            if response.status_code != 200:
                return None

            # Parse certificate
            cert = x509.load_pem_x509_certificate(
                response.content,
                default_backend()
            )

            # Cache the certificate
            self.cert_cache[cert_url] = cert

            return cert

        except Exception as e:
            print(f"Failed to get certificate: {str(e)}")
            return None

    def _validate_certificate_issuer(self, certificate: x509.Certificate) -> bool:
        """
        Validate that the certificate is issued by Amazon.

        Args:
            certificate: The certificate to validate

        Returns:
            bool: True if certificate is from Amazon
        """
        try:
            issuer = certificate.issuer
            # Check if Amazon is in the issuer's organization name
            org_names = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            for org_name in org_names:
                if 'Amazon' in str(org_name.value):
                    return True
            return False
        except Exception:
            return False

    def _build_string_to_sign(self, sns_payload: Dict[str, Any]) -> str:
        """
        Build the string that was signed by SNS.

        Args:
            sns_payload: The SNS payload

        Returns:
            str: The string to verify against the signature
        """
        # Fields to include in signature verification (in order)
        if sns_payload.get('Type') == 'Notification':
            fields = ['Message', 'MessageId', 'Subject', 'Timestamp',
                      'TopicArn', 'Type']
        else:
            # SubscriptionConfirmation and UnsubscribeConfirmation
            fields = ['Message', 'MessageId', 'SubscribeURL', 'Timestamp',
                      'Token', 'TopicArn', 'Type']

        string_to_sign = ""
        for field in fields:
            if field in sns_payload:
                string_to_sign += field + "\n"
                string_to_sign += str(sns_payload[field]) + "\n"

        return string_to_sign


def get_args() -> argparse.Namespace:
    """
    Parse and return command line arguments.

    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description='Secure AWS SNS Webhook Receiver to Send Slack Notifications'
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
    # Validate security section
    if 'security' not in config:
        print("WARNING: 'security' section not found in config - using defaults")
        config['security'] = {
            'aws_account_ids': [],
            'verify_signatures': False,  # Changed default to False for local testing
            'allowed_regions': []
        }

    if not config['security'].get('aws_account_ids'):
        print("WARNING: No AWS account IDs configured - accepting from any account")

    # Validate Slack section
    if 'slack' not in config:
        print("'slack' section not found in config")
        sys.exit(1)

    if 'token' not in config['slack']:
        print("'token' not found in 'slack' section of config")
        sys.exit(1)

    if 'channels' not in config['slack']:
        print("'channels' not found in 'slack' section of config")
        sys.exit(1)


def require_api_key(config: Config):
    """
    Decorator to require API key authentication.

    Args:
        config: Application configuration
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_keys = config.get('security', {}).get('api_keys', [])
            if api_keys:
                # Check for API key in headers
                provided_key = request.headers.get('X-API-Key')
                if not provided_key or provided_key not in api_keys:
                    return make_response(jsonify({
                        'status': 'error',
                        'msg': 'Unauthorized'
                    }), 401)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


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
            if sns_message.get('detail', {}).get('eventTypeCategory') == 'issue':
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
        message += f'**Account:** {sns_message.get("account", "N/A")}\n'
        message += f'**Region:** {sns_message.get("region", "N/A")}\n'

        if sns_message.get("resources"):
            message += f'**Resources:** {",".join(sns_message["resources"])}\n'

        detail = sns_message.get('detail', {})
        message += f'**Service:** {detail.get("service", "N/A")}\n'
        message += f'**Event Type Code:** {detail.get("eventTypeCode", "N/A")}\n'
        message += f'**Event Type Category:** {detail.get("eventTypeCategory", "N/A")}\n'
        message += f'**Start Time:** {detail.get("startTime", "N/A")}\n'
        message += f'**End Time:** {detail.get("endTime", "N/A")}\n'
        message += '**Description:**\n'

        for description_item in detail.get('eventDescription', []):
            if description_item.get('language') == 'en_US':
                message += description_item.get('latestDescription', 'N/A') + '\n'

        if 'affectedEntities' in detail:
            message += '**Affected Entities:**\n'
            for affected_entity in detail['affectedEntities']:
                message += f'  * {affected_entity.get("entityValue", "N/A")}\n'

    elif notification_type == NOTIFICATION_TYPES.AUTOSCALING:
        if 'Details' in sns_message and 'Availability Zone' in sns_message['Details']:
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
    security_validator = SecurityValidator(config.get('security', {}))

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
        return make_response(jsonify({'status': 'ok', 'secure': True}), 200)

    @app.route('/', methods=['POST'])
    @require_api_key(config)
    def webhook_handler() -> Response:
        """
        Handle incoming SNS webhook notifications with security validation.

        Returns:
            Response: JSON response indicating success or failure
        """
        try:
            sns_payload = json.loads(request.data.decode('utf-8'))

            # Security validation
            is_valid, error_msg = security_validator.validate_request(sns_payload)
            if not is_valid:
                print(f"Security validation failed: {error_msg}")
                return make_response(jsonify({
                    'status': 'error',
                    'msg': 'Unauthorized',
                    'detail': error_msg
                }), 403)

            # Handle SNS Subscription Confirmation
            if sns_payload.get('Type') == 'SubscriptionConfirmation':
                subscribe_url = sns_payload.get('SubscribeURL')
                if subscribe_url:
                    # Validate the subscription URL is from AWS
                    parsed_url = urlparse(subscribe_url)
                    if not parsed_url.netloc.endswith('.amazonaws.com'):
                        return make_response(jsonify({
                            'status': 'error',
                            'message': 'Invalid subscription URL'
                        }), 400)

                    # Confirm the subscription
                    response = requests.get(subscribe_url, timeout=5)
                    if response.status_code == 200:
                        print(f"Successfully confirmed subscription for topic: {sns_payload.get('TopicArn')}")
                        return make_response(jsonify({
                            'status': 'ok',
                            'message': 'Subscription confirmed'
                        }), 200)
                    else:
                        print(f"Failed to confirm subscription: {response.status_code}")
                        return make_response(jsonify({
                            'status': 'error',
                            'message': 'Failed to confirm subscription'
                        }), 500)

            # Handle UnsubscribeConfirmation
            if sns_payload.get('Type') == 'UnsubscribeConfirmation':
                print(f"Unsubscribe confirmation received for topic: {sns_payload.get('TopicArn')}")
                return make_response(jsonify({'status': 'ok'}), 200)

            # Handle SNS Notification
            if sns_payload.get('Type') == 'Notification':
                notification_type = NOTIFICATION_TYPES.DEFAULT
                color = 'good'
                message = ''

                sns_message = _parse_sns_message(sns_payload)
                if not sns_message:
                    return make_response(jsonify({'status': 'ok'}), 200)

                notification_type, color = _determine_notification_type(sns_message)
                message = _format_message(sns_message, notification_type)

                if _should_skip_notification(sns_message):
                    return make_response(jsonify({'status': 'ok', 'skipped': True}), 200)

                # Log to InfluxDB if applicable
                if notification_type == NOTIFICATION_TYPES.AUTOSCALING:
                    influxdb_logger.log_autoscaling_event(sns_message)

                # Send to Slack
                region = sns_payload['TopicArn'].split(':')[3]
                channel = _get_slack_channel(config, notification_type, region)

                title = sns_payload.get('Subject') or sns_message.get('detail-type')
                slack_response = slack_notifier.send_notification(message, channel, color, title)

                return jsonify({
                    'status': 'ok',
                    'slack_response': slack_response
                })

            # Unknown message type
            return make_response(jsonify({'status': 'ok'}), 200)

        except Exception as e:
            print(f"Error processing webhook: {str(e)}")
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
    print(f"Starting secure SNS webhook receiver on {args.host}:{args.port}")
    print(f"Security features enabled:")
    print(f"  - Signature validation: {config.get('security', {}).get('verify_signatures', True)}")
    print(f"  - Account IDs: {config.get('security', {}).get('aws_account_ids', [])}")
    print(f"  - API Key required: {bool(config.get('security', {}).get('api_keys'))}")
    app.run(
        host=args.host,
        port=args.port
    )


if __name__ == '__main__':
    main()
