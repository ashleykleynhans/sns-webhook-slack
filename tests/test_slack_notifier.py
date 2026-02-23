from unittest.mock import patch, MagicMock
import pytest
from webhook import SlackNotifier


class TestSlackNotifierInit:
    def test_default_url(self):
        config = {
            'slack': {'token': 'xoxb-test'},
        }
        notifier = SlackNotifier(config)
        assert notifier.slack_url == 'https://slack.com/api/chat.postMessage'
        assert notifier.slack_token == 'xoxb-test'

    def test_custom_url(self):
        config = {
            'slack': {
                'token': 'xoxb-test',
                'url': 'https://hooks.slack.com/services',
            },
        }
        notifier = SlackNotifier(config)
        assert notifier.slack_url == 'https://hooks.slack.com/services/xoxb-test'

    def test_missing_token(self):
        config = {'slack': {}}
        notifier = SlackNotifier(config)
        assert notifier.slack_token == 'not-configured'


class TestSendNotification:
    def test_not_configured(self):
        config = {'slack': {'token': 'not-configured'}}
        notifier = SlackNotifier(config)
        result = notifier.send_notification('msg', 'channel')
        assert result['ok'] is False
        assert result['error'] == 'not_configured'

    @patch('webhook.requests.post')
    def test_successful_send(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ok': True}
        mock_post.return_value = mock_response

        config = {'slack': {'token': 'xoxb-test'}}
        notifier = SlackNotifier(config)
        result = notifier.send_notification('test message', 'test-channel', 'good')

        assert result == {'ok': True}
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs['json']['channel'] == '#test-channel'

    @patch('webhook.requests.post')
    def test_send_with_title(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ok': True}
        mock_post.return_value = mock_response

        config = {'slack': {'token': 'xoxb-test'}}
        notifier = SlackNotifier(config)
        result = notifier.send_notification('msg', 'ch', 'good', title='Test Title')

        payload = mock_post.call_args.kwargs['json']
        assert payload['attachments'][0]['title'] == 'Test Title'

    @patch('webhook.requests.post')
    def test_http_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        config = {'slack': {'token': 'xoxb-test'}}
        notifier = SlackNotifier(config)
        result = notifier.send_notification('msg', 'ch')
        assert result['ok'] is False
        assert 'status_500' in result['error']

    @patch('webhook.requests.post', side_effect=Exception('network error'))
    def test_exception(self, mock_post):
        config = {'slack': {'token': 'xoxb-test'}}
        notifier = SlackNotifier(config)
        result = notifier.send_notification('msg', 'ch')
        assert result['ok'] is False
        assert 'network error' in result['error']
