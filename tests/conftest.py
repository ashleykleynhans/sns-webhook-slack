import json
import pytest
import webhook


@pytest.fixture
def test_config():
    return {
        'slack': {
            'token': 'xoxb-test-token',
            'channels': {
                'default': {
                    'us-east-1': 'aws-alerts-prod',
                    'us-east-2': 'aws-alerts-test',
                },
                'autoscaling': {
                    'us-east-1': 'aws-autoscaling-prod',
                },
                'health': {
                    'us-east-1': 'aws-health-prod',
                },
            },
        },
        'security': {
            'aws_account_ids': ['123456789012'],
            'verify_signatures': False,
            'allowed_regions': ['us-east-1', 'us-east-2'],
            'api_keys': [],
            'allowed_topic_patterns': [],
        },
        'environments': {
            'us-east-1': 'prod',
            'us-east-2': 'test',
        },
        'influxdb': {
            'prod': {
                'url': 'http://localhost:8086',
                'token': 'test-token',
                'org': 'TestOrg',
                'bucket': 'TestBucket',
            },
        },
    }


@pytest.fixture
def app(test_config):
    app = webhook.create_app(test_config)
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def sns_notification_payload():
    """A basic SNS Notification payload wrapping a Health event."""
    return {
        'Type': 'Notification',
        'MessageId': 'test-message-id',
        'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test-topic',
        'Subject': 'AWS Health Event',
        'Message': json.dumps({
            'detail-type': 'AWS Health Event',
            'account': '123456789012',
            'region': 'us-east-1',
            'resources': ['redis-cluster-prod'],
            'detail': {
                'service': 'ELASTICACHE',
                'eventTypeCode': 'AWS_ELASTICACHE_UPDATE_COMPLETED',
                'eventTypeCategory': 'accountNotification',
                'startTime': 'Mon, 23 Feb 2026 08:28:55 GMT',
                'endTime': 'Mon, 23 Feb 2026 08:28:55 GMT',
                'eventDescription': [
                    {
                        'language': 'en_US',
                        'latestDescription': 'Your ElastiCache cluster is up to date.\\n\\nSee FAQs.',
                    }
                ],
                'affectedEntities': [
                    {'entityValue': 'redis-cluster-prod'}
                ],
            },
        }),
        'Timestamp': '2026-02-23T08:28:55.000Z',
        'SignatureVersion': '1',
        'Signature': 'dGVzdA==',
        'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/cert.pem',
    }


@pytest.fixture
def sns_subscription_payload():
    return {
        'Type': 'SubscriptionConfirmation',
        'MessageId': 'test-message-id',
        'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test-topic',
        'Message': 'You have chosen to subscribe',
        'SubscribeURL': 'https://sns.us-east-1.amazonaws.com/confirm?token=abc',
        'Token': 'abc',
        'Timestamp': '2026-02-23T08:28:55.000Z',
        'SignatureVersion': '1',
        'Signature': 'dGVzdA==',
        'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/cert.pem',
    }
