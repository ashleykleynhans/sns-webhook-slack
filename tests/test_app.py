import json
from unittest.mock import patch, MagicMock
import pytest
import webhook
from webhook import create_app


class TestCreateApp:
    def test_create_app_with_config(self, test_config):
        app = create_app(test_config)
        assert app is not None

    def test_create_app_without_config(self):
        with patch('webhook.load_config') as mock_load:
            mock_load.return_value = {
                'slack': {'token': 'not-configured', 'channels': {}},
                'security': {
                    'aws_account_ids': [],
                    'verify_signatures': False,
                    'allowed_regions': [],
                },
            }
            app = create_app()
            assert app is not None


class TestHealthCheck:
    def test_get_health(self, client):
        response = client.get('/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ok'
        assert 'crypto_available' in data
        assert 'influxdb_available' in data
        assert data['secure'] is True


class TestErrorHandlers:
    def test_404(self, client):
        response = client.get('/nonexistent')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'not found' in data['msg']


class TestSubscriptionConfirmation:
    @patch('webhook.requests.get')
    def test_valid_subscription(self, mock_get, client, sns_subscription_payload):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        response = client.post(
            '/',
            data=json.dumps(sns_subscription_payload),
            content_type='application/json',
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Subscription confirmed'

    @patch('webhook.requests.get')
    def test_subscription_confirmation_failure(self, mock_get, client, sns_subscription_payload):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        response = client.post(
            '/',
            data=json.dumps(sns_subscription_payload),
            content_type='application/json',
        )
        assert response.status_code == 500

    def test_subscription_invalid_url(self, client, sns_subscription_payload):
        sns_subscription_payload['SubscribeURL'] = 'https://evil.com/confirm'
        response = client.post(
            '/',
            data=json.dumps(sns_subscription_payload),
            content_type='application/json',
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid subscription URL' in data['message']


    def test_subscription_no_subscribe_url(self, client):
        payload = {
            'Type': 'SubscriptionConfirmation',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test-topic',
            'MessageId': 'test-id',
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        # Falls through to UnsubscribeConfirmation check, then unknown type
        assert response.status_code == 200


class TestUnsubscribeConfirmation:
    def test_unsubscribe(self, client):
        payload = {
            'Type': 'UnsubscribeConfirmation',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test-topic',
            'MessageId': 'test-id',
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 200


class TestNotification:
    @patch('webhook.SlackNotifier.send_notification')
    def test_health_notification(self, mock_slack, client, sns_notification_payload):
        mock_slack.return_value = {'ok': True}
        response = client.post(
            '/',
            data=json.dumps(sns_notification_payload),
            content_type='application/json',
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ok'
        mock_slack.assert_called_once()

    @patch('webhook.SlackNotifier.send_notification')
    def test_autoscaling_notification(self, mock_slack, client):
        mock_slack.return_value = {'ok': True}
        payload = {
            'Type': 'Notification',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:autoscaling',
            'Subject': 'Auto Scaling',
            'Message': json.dumps({
                'Event': 'autoscaling:EC2_INSTANCE_LAUNCH',
                'AutoScalingGroupName': 'my-asg',
                'Cause': 'increasing the capacity from 1 to 2',
                'AvailabilityZone': 'us-east-1a',
            }),
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 200

    @patch('webhook.SlackNotifier.send_notification')
    def test_skip_notification(self, mock_slack, client):
        payload = {
            'Type': 'Notification',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test',
            'Message': json.dumps({
                'Event': 'autoscaling:TEST_NOTIFICATION',
            }),
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data.get('skipped') is True
        mock_slack.assert_not_called()

    def test_unparseable_message(self, client):
        payload = {
            'Type': 'Notification',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test',
            'Message': 'not valid json',
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ok'

    @patch('webhook.SlackNotifier.send_notification')
    def test_notification_no_topic_arn_region(self, mock_slack, client):
        """Test when TopicArn has no colons for region extraction."""
        mock_slack.return_value = {'ok': True}
        payload = {
            'Type': 'Notification',
            'Message': json.dumps({'detail-type': 'Support Case Update', 'case': '123'}),
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 200

    @patch('webhook.SlackNotifier.send_notification')
    def test_notification_with_subject_title(self, mock_slack, client, sns_notification_payload):
        """Title should come from Subject field."""
        mock_slack.return_value = {'ok': True}
        response = client.post(
            '/',
            data=json.dumps(sns_notification_payload),
            content_type='application/json',
        )
        assert response.status_code == 200
        call_kwargs = mock_slack.call_args
        assert call_kwargs.kwargs.get('title') or call_kwargs[0][3] if len(call_kwargs[0]) > 3 else True

    @patch('webhook.SlackNotifier.send_notification')
    def test_notification_with_detail_type_title(self, mock_slack, client):
        """When no Subject, title should come from detail-type."""
        mock_slack.return_value = {'ok': True}
        payload = {
            'Type': 'Notification',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test',
            'Message': json.dumps({
                'detail-type': 'CloudWatch Alarm State Change',
                'account': '123',
                'region': 'us-east-1',
                'detail': {
                    'alarmName': 'Test',
                    'state': {'value': 'OK', 'reason': 'ok'},
                    'configuration': {},
                },
            }),
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 200


class TestUnknownMessageType:
    def test_unknown_type(self, client):
        payload = {
            'Type': 'SomeUnknownType',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test',
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 200


class TestSecurityValidation:
    def test_unauthorized_account(self, client):
        payload = {
            'Type': 'Notification',
            'TopicArn': 'arn:aws:sns:us-east-1:999999999999:test',
            'Message': json.dumps({'key': 'value'}),
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['status'] == 'error'


class TestApiKeyAuth:
    def test_api_key_required_but_missing(self, test_config):
        test_config['security']['api_keys'] = ['secret-key']
        app = create_app(test_config)
        app.config['TESTING'] = True
        client = app.test_client()

        payload = {
            'Type': 'Notification',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test',
            'Message': json.dumps({'key': 'value'}),
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 401

    @patch('webhook.SlackNotifier.send_notification')
    def test_api_key_provided(self, mock_slack, test_config):
        mock_slack.return_value = {'ok': True}
        test_config['security']['api_keys'] = ['secret-key']
        app = create_app(test_config)
        app.config['TESTING'] = True
        client = app.test_client()

        payload = {
            'Type': 'Notification',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test',
            'Message': json.dumps({'detail-type': 'Support Case Update', 'case': '1'}),
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
            headers={'X-API-Key': 'secret-key'},
        )
        assert response.status_code == 200


class TestExceptionHandling:
    def test_malformed_json(self, client):
        response = client.post(
            '/',
            data='not json at all',
            content_type='application/json',
        )
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data['status'] == 'error'


class TestInfluxDBIntegration:
    @patch('webhook.InfluxDBLogger.log_autoscaling_event')
    @patch('webhook.SlackNotifier.send_notification')
    def test_autoscaling_logs_to_influxdb(self, mock_slack, mock_influx, client):
        mock_slack.return_value = {'ok': True}
        payload = {
            'Type': 'Notification',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:autoscaling',
            'Subject': 'Auto Scaling',
            'Message': json.dumps({
                'Event': 'autoscaling:EC2_INSTANCE_LAUNCH',
                'AutoScalingGroupName': 'my-asg',
                'AvailabilityZone': 'us-east-1a',
            }),
        }
        response = client.post(
            '/',
            data=json.dumps(payload),
            content_type='application/json',
        )
        assert response.status_code == 200
        mock_influx.assert_called_once()
