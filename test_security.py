#!/usr/bin/env python3
"""
Security helper script for SNS Webhook Receiver.
Generates API keys and tests security features.
"""

import os
import sys
import json
import secrets
import hashlib
import argparse
import requests
import base64
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID


def generate_api_key(length=32, format='hex'):
    """
    Generate a secure API key.
    
    Args:
        length: Key length in bytes
        format: Output format ('hex', 'base64', 'urlsafe')
    
    Returns:
        str: Generated API key
    """
    if format == 'hex':
        return secrets.token_hex(length)
    elif format == 'base64':
        return secrets.token_bytes(length).hex()
    elif format == 'urlsafe':
        return secrets.token_urlsafe(length)
    else:
        raise ValueError(f"Unknown format: {format}")


def generate_test_sns_message(
    account_id="123456789012",
    region="us-east-1",
    topic_name="test-topic",
    message_type="Notification",
    sign_message=False
):
    """
    Generate a test SNS message for security testing.
    
    Args:
        account_id: AWS account ID
        region: AWS region
        topic_name: SNS topic name
        message_type: Type of SNS message
        sign_message: Whether to sign the message (requires private key)
    
    Returns:
        dict: Test SNS message
    """
    topic_arn = f"arn:aws:sns:{region}:{account_id}:{topic_name}"
    
    if message_type == "SubscriptionConfirmation":
        sns_message = {
            "Type": "SubscriptionConfirmation",
            "MessageId": secrets.token_hex(16),
            "Token": secrets.token_hex(32),
            "TopicArn": topic_arn,
            "Message": "You have chosen to subscribe to this topic.",
            "SubscribeURL": f"https://sns.{region}.amazonaws.com/?Action=ConfirmSubscription&TopicArn={topic_arn}&Token={secrets.token_hex(32)}",
            "Timestamp": datetime.utcnow().isoformat() + "Z"
        }
    else:
        # Create a health event message
        health_event = {
            "detail-type": "AWS Health Event",
            "account": account_id,
            "region": region,
            "resources": [],
            "detail": {
                "eventArn": f"arn:aws:health:{region}::{secrets.token_hex(16)}",
                "service": "EC2",
                "eventTypeCode": "AWS_EC2_INSTANCE_STOP",
                "eventTypeCategory": "issue",
                "startTime": datetime.utcnow().isoformat() + "Z",
                "endTime": (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z",
                "eventDescription": [{
                    "language": "en_US",
                    "latestDescription": "EC2 instance stopped due to maintenance"
                }]
            }
        }
        
        sns_message = {
            "Type": "Notification",
            "MessageId": secrets.token_hex(16),
            "TopicArn": topic_arn,
            "Subject": "AWS Health Event",
            "Message": json.dumps(health_event),
            "Timestamp": datetime.utcnow().isoformat() + "Z"
        }
    
    if sign_message:
        # This would require a private key - for testing only
        sns_message["SigningCertURL"] = f"https://sns.{region}.amazonaws.com/SimpleNotificationService-{secrets.token_hex(16)}.pem"
        sns_message["Signature"] = base64.b64encode(b"fake_signature_for_testing").decode('utf-8')
    
    return sns_message


def test_endpoint_security(endpoint_url, api_key=None, test_cases=None):
    """
    Test various security scenarios against the endpoint.
    
    Args:
        endpoint_url: The webhook endpoint URL
        api_key: API key for authentication
        test_cases: List of test cases to run
    """
    if test_cases is None:
        test_cases = ['api_key', 'invalid_account', 'invalid_signature', 'valid']
    
    results = []
    headers = {'Content-Type': 'application/json'}
    if api_key:
        headers['X-API-Key'] = api_key
    
    print(f"\nTesting endpoint: {endpoint_url}")
    print("=" * 50)
    
    # Test 1: API Key validation
    if 'api_key' in test_cases:
        print("\n1. Testing API key validation...")
        # Without API key
        test_headers = {'Content-Type': 'application/json'}
        response = requests.post(
            endpoint_url,
            json={"Type": "Notification", "Message": "test"},
            headers=test_headers
        )
        print(f"   Without API key: {response.status_code} - {'✓ Blocked' if response.status_code == 401 else '✗ Not blocked'}")
        
        # With wrong API key
        test_headers['X-API-Key'] = 'wrong-key'
        response = requests.post(
            endpoint_url,
            json={"Type": "Notification", "Message": "test"},
            headers=test_headers
        )
        print(f"   With wrong API key: {response.status_code} - {'✓ Blocked' if response.status_code == 401 else '✗ Not blocked'}")
    
    # Test 2: Invalid AWS account
    if 'invalid_account' in test_cases:
        print("\n2. Testing AWS account validation...")
        message = generate_test_sns_message(
            account_id="999999999999",  # Invalid account
            message_type="Notification"
        )
        response = requests.post(endpoint_url, json=message, headers=headers)
        print(f"   Invalid account: {response.status_code} - {'✓ Blocked' if response.status_code == 403 else '✗ Not blocked'}")
        if response.status_code != 403:
            print(f"   Response: {response.json()}")
    
    # Test 3: Invalid signature
    if 'invalid_signature' in test_cases:
        print("\n3. Testing signature validation...")
        message = generate_test_sns_message(
            account_id="123456789012",
            message_type="Notification",
            sign_message=True
        )
        response = requests.post(endpoint_url, json=message, headers=headers)
        print(f"   Invalid signature: {response.status_code} - {'✓ Blocked' if response.status_code == 403 else '✗ Not blocked'}")
    
    # Test 4: Valid message (would need real SNS message)
    if 'valid' in test_cases:
        print("\n4. Testing valid message handling...")
        message = generate_test_sns_message(
            account_id="123456789012",
            message_type="Notification"
        )
        # Remove signature fields for this test
        message.pop('SigningCertURL', None)
        message.pop('Signature', None)
        
        response = requests.post(endpoint_url, json=message, headers=headers)
        print(f"   Valid message: {response.status_code}")
        if response.status_code == 200:
            print("   ✓ Message accepted (signature validation may be disabled)")
        else:
            print(f"   Response: {response.json()}")
    
    print("\n" + "=" * 50)
    print("Security testing complete")


def update_config_security(config_file='config.yml'):
    """
    Interactive tool to update security settings in config.yml.
    """
    import yaml
    
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        config = {}
    
    if 'security' not in config:
        config['security'] = {}
    
    print("\nSecurity Configuration Helper")
    print("=" * 40)
    
    # AWS Account IDs
    print("\n1. AWS Account IDs (comma-separated):")
    current = config['security'].get('aws_account_ids', [])
    print(f"   Current: {', '.join(current) if current else 'None'}")
    new_accounts = input("   Enter new account IDs (or press Enter to keep current): ")
    if new_accounts:
        config['security']['aws_account_ids'] = [a.strip() for a in new_accounts.split(',')]
    
    # API Keys
    print("\n2. API Key Configuration:")
    if input("   Generate new API key? (y/n): ").lower() == 'y':
        key = generate_api_key()
        print(f"   Generated API key: {key}")
        if 'api_keys' not in config['security']:
            config['security']['api_keys'] = []
        config['security']['api_keys'].append(key)
        print("   ✓ API key added to configuration")
    
    # Signature validation
    print("\n3. Signature Validation:")
    current = config['security'].get('verify_signatures', True)
    print(f"   Current: {current}")
    if input("   Enable signature validation? (y/n): ").lower() == 'n':
        config['security']['verify_signatures'] = False
    else:
        config['security']['verify_signatures'] = True
    
    # Save configuration
    if input("\nSave configuration? (y/n): ").lower() == 'y':
        with open(config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        print(f"✓ Configuration saved to {config_file}")
    else:
        print("Configuration not saved")


def main():
    parser = argparse.ArgumentParser(description='Security helper for SNS Webhook')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Generate API key command
    gen_parser = subparsers.add_parser('generate-key', help='Generate API key')
    gen_parser.add_argument('--length', type=int, default=32, help='Key length in bytes')
    gen_parser.add_argument('--format', choices=['hex', 'base64', 'urlsafe'], default='hex', help='Output format')
    gen_parser.add_argument('--count', type=int, default=1, help='Number of keys to generate')
    
    # Test endpoint command
    test_parser = subparsers.add_parser('test', help='Test endpoint security')
    test_parser.add_argument('endpoint', help='Webhook endpoint URL')
    test_parser.add_argument('--api-key', help='API key for authentication')
    test_parser.add_argument('--tests', nargs='+', 
                            choices=['api_key', 'invalid_account', 'invalid_signature', 'valid'],
                            help='Specific tests to run')
    
    # Update config command
    config_parser = subparsers.add_parser('config', help='Update security configuration')
    config_parser.add_argument('--file', default='config.yml', help='Config file path')
    
    # Generate test message command
    msg_parser = subparsers.add_parser('generate-message', help='Generate test SNS message')
    msg_parser.add_argument('--account-id', default='123456789012', help='AWS account ID')
    msg_parser.add_argument('--region', default='us-east-1', help='AWS region')
    msg_parser.add_argument('--topic', default='test-topic', help='Topic name')
    msg_parser.add_argument('--type', choices=['Notification', 'SubscriptionConfirmation'], 
                           default='Notification', help='Message type')
    msg_parser.add_argument('--sign', action='store_true', help='Add fake signature')
    
    args = parser.parse_args()
    
    if args.command == 'generate-key':
        print(f"\nGenerating {args.count} API key(s):\n")
        for i in range(args.count):
            key = generate_api_key(args.length, args.format)
            print(f"API Key {i+1}: {key}")
        print(f"\nAdd to config.yml under security.api_keys")
    
    elif args.command == 'test':
        test_endpoint_security(args.endpoint, args.api_key, args.tests)
    
    elif args.command == 'config':
        update_config_security(args.file)
    
    elif args.command == 'generate-message':
        message = generate_test_sns_message(
            account_id=args.account_id,
            region=args.region,
            topic_name=args.topic,
            message_type=args.type,
            sign_message=args.sign
        )
        print(json.dumps(message, indent=2))
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
