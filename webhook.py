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
import os
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

# Try to import InfluxDB (optional)
try:
    from influxdb_client import InfluxDBClient, Point, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS
    INFLUXDB_AVAILABLE = True
except ImportError:
    INFLUXDB_AVAILABLE = False

# Try to import cryptography (often fails in Lambda)
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("WARNING: cryptography not available - signature validation disabled")


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
    ACM: str = 'acm'
    REKOGNITION: str = 'rekognition'
    AWS_SERVICE: str = 'aws-service'
    SECURITY_HUB: str = 'security-hub'
    TRUSTED_ADVISOR: str = 'trusted-advisor'
    CONFIG: str = 'config'
    CLOUDWATCH: str = 'cloudwatch'


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
]


class SecurityValidator:
    """Handle security validation for incoming SNS messages."""

    def __init__(self, config: SecurityConfig):
        """Initialize security validator with configuration."""
        self.config = config
        self.cert_cache: Dict[str, Any] = {}

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

        # Validate signature if enabled AND cryptography is available
        if self.config.get('verify_signatures', False) and CRYPTO_AVAILABLE:
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
        try:
            arn_parts = topic_arn.split(':')
            if len(arn_parts) < 6:
                return False, "Invalid ARN format"

            # Validate it's an SNS ARN
            if arn_parts[0] != 'arn' or arn_parts[2] != 'sns':
                return False, "Not an SNS ARN"

            # Extract and validate account ID
            account_id = arn_parts[4]
            allowed_accounts = self.config.get('aws_account_ids', [])
            if allowed_accounts and account_id not in allowed_accounts:
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
        if not CRYPTO_AVAILABLE:
            # Can't validate without cryptography library
            return True, ""

        try:
            # If signature validation is disabled, skip
            if not self.config.get('verify_signatures', False):
                return True, ""

            # Check if signature fields are present
            if 'SigningCertURL' not in sns_payload or 'Signature' not in sns_payload:
                # No signature fields - allow if verify_signatures is False
                if not self.config.get('verify_signatures', False):
                    return True, ""
                return False, "Missing signature fields"

            # Rest of validation only if cryptography is available
            cert_url = sns_payload['SigningCertURL']
            if not self._is_valid_cert_url(cert_url):
                return False, f"Invalid certificate URL: {cert_url}"

            # Get the certificate
            certificate = self._get_certificate(cert_url)
            if not certificate:
                return False, "Failed to retrieve certificate"

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
        """Validate that the certificate URL is from AWS."""
        try:
            parsed = urlparse(cert_url)
            if parsed.scheme != 'https':
                return False
            domain = parsed.netloc.lower()
            if not any(domain == valid_domain or domain.endswith(f'.{valid_domain}')
                       for valid_domain in VALID_CERT_DOMAINS):
                return False
            if not parsed.path.endswith('.pem'):
                return False
            return True
        except Exception:
            return False

    def _get_certificate(self, cert_url: str):
        """Retrieve and cache the certificate from the URL."""
        if not CRYPTO_AVAILABLE:
            return None

        try:
            # Check cache first
            if cert_url in self.cert_cache:
                return self.cert_cache[cert_url]

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

    def _build_string_to_sign(self, sns_payload: Dict[str, Any]) -> str:
        """Build the string that was signed by SNS."""
        if sns_payload.get('Type') == 'Notification':
            fields = ['Message', 'MessageId', 'Subject', 'Timestamp',
                      'TopicArn', 'Type']
        else:
            fields = ['Message', 'MessageId', 'SubscribeURL', 'Timestamp',
                      'Token', 'TopicArn', 'Type']

        string_to_sign = ""
        for field in fields:
            if field in sns_payload:
                string_to_sign += field + "\n"
                string_to_sign += str(sns_payload[field]) + "\n"

        return string_to_sign


def load_config() -> Config:
    """
    Load configuration from environment variables or config.yml file.
    Lambda-safe: returns defaults if config not found.
    """
    # First, try environment variables (preferred for Lambda)
    if os.environ.get('SLACK_TOKEN'):
        print("Loading config from environment variables")
        config = {
            'slack': {
                'token': os.environ.get('SLACK_TOKEN'),
                'channels': json.loads(os.environ.get('SLACK_CHANNELS', '{}'))
                if os.environ.get('SLACK_CHANNELS') else {},
                'url': os.environ.get('SLACK_URL')
            },
            'security': {
                'aws_account_ids': json.loads(os.environ.get('AWS_ACCOUNT_IDS', '[]'))
                if os.environ.get('AWS_ACCOUNT_IDS') else [],
                'verify_signatures': os.environ.get('VERIFY_SIGNATURES', 'false').lower() == 'true',
                'api_keys': json.loads(os.environ.get('API_KEYS', '[]'))
                if os.environ.get('API_KEYS') else [],
                'allowed_regions': json.loads(os.environ.get('ALLOWED_REGIONS', '[]'))
                if os.environ.get('ALLOWED_REGIONS') else [],
                'allowed_topic_patterns': json.loads(os.environ.get('ALLOWED_TOPIC_PATTERNS', '[]'))
                if os.environ.get('ALLOWED_TOPIC_PATTERNS') else []
            }
        }
        return config

    # Try to load from file
    config_files = ['config.yml', '/var/task/config.yml', './config.yml']

    for config_file in config_files:
        try:
            with open(config_file, 'r') as stream:
                print(f"Loading config from {config_file}")
                config = yaml.safe_load(stream)
                validate_config(config)
                return config
        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"Error loading {config_file}: {e}")
            continue

    # If no config found, return minimal default config
    print("WARNING: No config found, using defaults")
    return {
        'slack': {
            'token': 'not-configured',
            'channels': {
                'default': {'us-east-1': 'notifications'},
                'autoscaling': {'us-east-1': 'notifications'},
                'health': {'us-east-1': 'notifications'},
                'support': {'us-east-1': 'notifications'},
                'savings-plans': {'us-east-1': 'notifications'}
            }
        },
        'security': {
            'aws_account_ids': [],
            'verify_signatures': False,
            'allowed_regions': []
        }
    }


def validate_config(config: Config) -> None:
    """
    Validate and fix the configuration structure.
    Lambda-safe: adds defaults instead of exiting.
    """
    # Ensure security section exists
    if 'security' not in config:
        print("WARNING: 'security' section not found in config - adding defaults")
        config['security'] = {
            'aws_account_ids': [],
            'verify_signatures': False,
            'allowed_regions': []
        }

    # Ensure slack section exists
    if 'slack' not in config:
        print("WARNING: 'slack' section not found in config - adding defaults")
        config['slack'] = {
            'token': 'not-configured',
            'channels': {}
        }

    if 'token' not in config['slack']:
        print("WARNING: 'token' not found in 'slack' section - using default")
        config['slack']['token'] = 'not-configured'

    if 'channels' not in config['slack']:
        print("WARNING: 'channels' not found in 'slack' section - using defaults")
        config['slack']['channels'] = {}


def require_api_key(config: Config):
    """Decorator to require API key authentication."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_keys = config.get('security', {}).get('api_keys', [])
            if api_keys:
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
    """Parse the SNS message from the payload."""
    try:
        sns_message = sns_payload['Message']
        return json.loads(sns_message)
    except (KeyError, json.JSONDecodeError):
        return None


def _determine_notification_type(sns_message: Dict[str, Any]) -> tuple[str, str]:
    """Determine the notification type and color from the SNS message."""
    color = 'good'
    notification_type = NOTIFICATION_TYPES.DEFAULT

    if 'Event' in sns_message and sns_message['Event'] in COLORS:
        color = COLORS[sns_message['Event']]
        if 'autoscaling:' in sns_message['Event']:
            notification_type = NOTIFICATION_TYPES.AUTOSCALING
    elif 'detail-type' in sns_message:
        detail_type = sns_message['detail-type']

        # Support Cases
        if detail_type == 'Support Case Update':
            notification_type = NOTIFICATION_TYPES.SUPPORT

        # Savings Plans
        elif detail_type == 'Savings Plans State Change Alert':
            notification_type = NOTIFICATION_TYPES.SAVINGS_PLANS

        # AWS Health Events
        elif detail_type == 'AWS Health Event':
            notification_type = NOTIFICATION_TYPES.HEALTH
            if sns_message.get('detail', {}).get('eventTypeCategory') == 'issue':
                color = 'danger'

        # ACM Certificate notifications
        elif 'ACM' in detail_type or 'Certificate' in detail_type:
            notification_type = NOTIFICATION_TYPES.ACM
            # Certificate expiring or renewal failed is a warning
            if any(keyword in detail_type for keyword in ['Expiration', 'Expiring', 'Failed', 'Error']):
                color = 'warning'

        # Rekognition notifications
        elif 'Rekognition' in detail_type or detail_type == 'Amazon Rekognition End of Life Notice':
            notification_type = NOTIFICATION_TYPES.REKOGNITION
            # EOL notices are warnings
            if 'End of Life' in detail_type or 'EOL' in detail_type or 'Deprecat' in detail_type:
                color = 'warning'

        # Security Hub findings
        elif 'Security Hub' in detail_type or detail_type == 'Security Hub Findings - Imported':
            notification_type = NOTIFICATION_TYPES.SECURITY_HUB
            # Check severity
            if sns_message.get('detail', {}).get('findings', [{}])[0].get('Severity', {}).get('Label') in ['CRITICAL', 'HIGH']:
                color = 'danger'
            elif sns_message.get('detail', {}).get('findings', [{}])[0].get('Severity', {}).get('Label') == 'MEDIUM':
                color = 'warning'

        # Trusted Advisor
        elif 'Trusted Advisor' in detail_type:
            notification_type = NOTIFICATION_TYPES.TRUSTED_ADVISOR
            # Check status
            status = sns_message.get('detail', {}).get('status', '').lower()
            if status in ['error', 'red']:
                color = 'danger'
            elif status in ['warning', 'yellow']:
                color = 'warning'

        # AWS Config
        elif 'Config' in detail_type or detail_type == 'Config Rules Compliance Change':
            notification_type = NOTIFICATION_TYPES.CONFIG
            # Non-compliant resources are warnings
            if sns_message.get('detail', {}).get('newEvaluationResult', {}).get('complianceType') == 'NON_COMPLIANT':
                color = 'danger'

        # CloudWatch Alarms
        elif 'CloudWatch Alarm' in detail_type or detail_type == 'CloudWatch Alarm State Change':
            notification_type = NOTIFICATION_TYPES.CLOUDWATCH
            # Alarm state determines color
            alarm_state = sns_message.get('detail', {}).get('state', {}).get('value', '').upper()
            if alarm_state == 'ALARM':
                color = 'danger'
            elif alarm_state == 'INSUFFICIENT_DATA':
                color = 'warning'

        # Generic AWS Service events
        elif 'AWS' in detail_type and notification_type == NOTIFICATION_TYPES.DEFAULT:
            notification_type = NOTIFICATION_TYPES.AWS_SERVICE

    return notification_type, color


def _format_message(sns_message: Dict[str, Any], notification_type: str) -> str:
    """Format the message based on notification type."""
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

    elif notification_type == NOTIFICATION_TYPES.ACM:
        message += f'**Account:** {sns_message.get("account", "N/A")}\n'
        message += f'**Region:** {sns_message.get("region", "N/A")}\n'
        message += f'**Time:** {sns_message.get("time", "N/A")}\n'

        detail = sns_message.get('detail', {})
        if 'DaysToExpiry' in detail:
            message += f'**Days to Expiry:** {detail.get("DaysToExpiry", "N/A")}\n'
        if 'CommonName' in detail:
            message += f'**Certificate:** {detail.get("CommonName", "N/A")}\n'
        if 'certificateArn' in detail:
            message += f'**Certificate ARN:** {detail.get("certificateArn", "N/A")}\n'

        # Include any other detail fields
        for key, value in detail.items():
            if key not in ['DaysToExpiry', 'CommonName', 'certificateArn']:
                message += f'**{key}:** {value}\n'

    elif notification_type == NOTIFICATION_TYPES.REKOGNITION:
        message += f'**Account:** {sns_message.get("account", "N/A")}\n'
        message += f'**Region:** {sns_message.get("region", "N/A")}\n'
        message += f'**Time:** {sns_message.get("time", "N/A")}\n'

        detail = sns_message.get('detail', {})
        for key, value in detail.items():
            message += f'**{key}:** {value}\n'

    elif notification_type == NOTIFICATION_TYPES.SECURITY_HUB:
        message += f'**Account:** {sns_message.get("account", "N/A")}\n'
        message += f'**Region:** {sns_message.get("region", "N/A")}\n'
        message += f'**Time:** {sns_message.get("time", "N/A")}\n'

        findings = sns_message.get('detail', {}).get('findings', [])
        if findings:
            for finding in findings[:5]:  # Limit to first 5 findings
                message += '\n**Finding:**\n'
                message += f'  **Title:** {finding.get("Title", "N/A")}\n'
                message += f'  **Severity:** {finding.get("Severity", {}).get("Label", "N/A")}\n'
                message += f'  **Type:** {finding.get("Types", ["N/A"])[0] if finding.get("Types") else "N/A"}\n'
                message += f'  **Description:** {finding.get("Description", "N/A")}\n'
                if 'Resources' in finding:
                    message += f'  **Resources:** {", ".join([r.get("Id", "N/A") for r in finding["Resources"][:3]])}\n'

    elif notification_type == NOTIFICATION_TYPES.TRUSTED_ADVISOR:
        message += f'**Account:** {sns_message.get("account", "N/A")}\n'
        message += f'**Region:** {sns_message.get("region", "N/A")}\n'
        message += f'**Time:** {sns_message.get("time", "N/A")}\n'

        detail = sns_message.get('detail', {})
        message += f'**Check Name:** {detail.get("check-name", "N/A")}\n'
        message += f'**Status:** {detail.get("status", "N/A")}\n'
        message += f'**Resource ID:** {detail.get("resource_id", "N/A")}\n'

        for key, value in detail.items():
            if key not in ['check-name', 'status', 'resource_id']:
                message += f'**{key}:** {value}\n'

    elif notification_type == NOTIFICATION_TYPES.CONFIG:
        message += f'**Account:** {sns_message.get("account", "N/A")}\n'
        message += f'**Region:** {sns_message.get("region", "N/A")}\n'
        message += f'**Time:** {sns_message.get("time", "N/A")}\n'

        detail = sns_message.get('detail', {})
        message += f'**Config Rule:** {detail.get("configRuleName", "N/A")}\n'

        new_result = detail.get('newEvaluationResult', {})
        if new_result:
            message += f'**Compliance Type:** {new_result.get("complianceType", "N/A")}\n'
            message += f'**Resource Type:** {new_result.get("evaluationResultIdentifier", {}).get("evaluationResultQualifier", {}).get("resourceType", "N/A")}\n'
            message += f'**Resource ID:** {new_result.get("evaluationResultIdentifier", {}).get("evaluationResultQualifier", {}).get("resourceId", "N/A")}\n'

    elif notification_type == NOTIFICATION_TYPES.CLOUDWATCH:
        message += f'**Account:** {sns_message.get("account", "N/A")}\n'
        message += f'**Region:** {sns_message.get("region", "N/A")}\n'
        message += f'**Time:** {sns_message.get("time", "N/A")}\n'

        detail = sns_message.get('detail', {})
        message += f'**Alarm Name:** {detail.get("alarmName", "N/A")}\n'

        state = detail.get('state', {})
        message += f'**State:** {state.get("value", "N/A")}\n'
        message += f'**Reason:** {state.get("reason", "N/A")}\n'

        configuration = detail.get('configuration', {})
        if 'description' in configuration:
            message += f'**Description:** {configuration.get("description", "N/A")}\n'

    elif notification_type == NOTIFICATION_TYPES.AWS_SERVICE:
        # Format generic AWS service events with structure
        message += f'**Account:** {sns_message.get("account", "N/A")}\n'
        message += f'**Region:** {sns_message.get("region", "N/A")}\n'
        message += f'**Time:** {sns_message.get("time", "N/A")}\n'
        message += f'**Source:** {sns_message.get("source", "N/A")}\n'

        detail = sns_message.get('detail', {})
        for key, value in detail.items():
            message += f'**{key}:** {value}\n'

    else:
        # Default formatter for unrecognized types
        for msg_item in sns_message.keys():
            message += f'{msg_item}: {sns_message[msg_item]}\n'

    return message


def _should_skip_notification(sns_message: Dict[str, Any]) -> bool:
    """Determine if the notification should be skipped."""
    return 'Event' in sns_message and sns_message['Event'] in EXCLUDE


def _get_slack_channel(config: Config, notification_type: str, region: str) -> str:
    """Get the appropriate Slack channel for the notification."""
    channels = config['slack'].get('channels', {})

    # Try to find the channel
    if notification_type in channels:
        if region in channels[notification_type]:
            return channels[notification_type][region]
        # If region not found, return first available
        if channels[notification_type]:
            return list(channels[notification_type].values())[0]

    # Fallback to default
    if 'default' in channels:
        if region in channels['default']:
            return channels['default'][region]
        if channels['default']:
            return list(channels['default'].values())[0]

    # Ultimate fallback
    return 'notifications'


class InfluxDBLogger:
    """Handle logging of autoscaling events to InfluxDB."""

    def __init__(self, config: Config):
        """Initialize InfluxDB logger with configuration."""
        self.config = config
        self.enabled = INFLUXDB_AVAILABLE and 'influxdb' in config

    def log_autoscaling_event(self, message: Dict[str, Any]) -> None:
        """Log autoscaling event to InfluxDB."""
        if not self.enabled:
            return

        try:
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
        if not INFLUXDB_AVAILABLE:
            return

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
            f"{config['slack'].get('url')}/{config['slack'].get('token')}"
            if 'url' in config.get('slack', {})
            else 'https://slack.com/api/chat.postMessage'
        )
        self.slack_token = config['slack'].get('token', 'not-configured')

    def send_notification(self, message: str, channel: str, color: str = 'good', title: Optional[str] = None) -> Dict[str, Any]:
        """Send notification to Slack."""
        if self.slack_token == 'not-configured':
            print("Slack not configured, skipping notification")
            return {'ok': False, 'error': 'not_configured'}

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

        try:
            response = requests.post(
                url=self.slack_url,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {self.slack_token}'
                },
                json=slack_payload,
                timeout=10
            )

            if response.status_code != 200:
                print(f'Slack API error: Status {response.status_code}')
                return {'ok': False, 'error': f'status_{response.status_code}'}

            return response.json()
        except Exception as e:
            print(f'Slack notification failed: {e}')
            return {'ok': False, 'error': str(e)}


def create_app(config: Config = None) -> Flask:
    """Create and configure Flask application."""
    app = Flask(__name__)

    # Use provided config or load one
    if config is None:
        config = load_config()

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
        return make_response(jsonify({
            'status': 'ok',
            'secure': True,
            'crypto_available': CRYPTO_AVAILABLE,
            'influxdb_available': INFLUXDB_AVAILABLE
        }), 200)

    @app.route('/', methods=['POST'])
    @require_api_key(config)
    def webhook_handler() -> Response:
        """Handle incoming SNS webhook notifications with security validation."""
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
                region = sns_payload.get('TopicArn', '').split(':')[3] if ':' in sns_payload.get('TopicArn', '') else 'us-east-1'
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


# Create app for Lambda/Zappa
# This must succeed even if config is missing
try:
    config = load_config()
    app = create_app(config)
except Exception as e:
    print(f"WARNING: Failed to load config, using defaults: {e}")
    app = create_app()


def main() -> None:
    """Main application entry point for local development."""
    args = get_args()
    print(f"Starting secure SNS webhook receiver on {args.host}:{args.port}")
    print(f"Security features enabled:")
    print(f"  - Signature validation: {config.get('security', {}).get('verify_signatures', False)}")
    print(f"  - Account IDs: {config.get('security', {}).get('aws_account_ids', [])}")
    print(f"  - API Key required: {bool(config.get('security', {}).get('api_keys'))}")
    app.run(host=args.host, port=args.port)


def get_args() -> argparse.Namespace:
    """Parse and return command line arguments."""
    parser = argparse.ArgumentParser(
        description='Secure AWS SNS Webhook Receiver to Send Slack Notifications'
    )
    parser.add_argument('-p', '--port', help='Port to listen on', type=int, default=8090)
    parser.add_argument('-H', '--host', help='Host to bind to', default='0.0.0.0')
    return parser.parse_args()


if __name__ == '__main__':
    main()
