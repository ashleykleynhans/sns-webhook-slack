import json
import os
from unittest.mock import patch, mock_open, MagicMock
import pytest
import yaml
from webhook import load_config, validate_config


class TestLoadConfig:
    def test_load_from_env_vars(self):
        env = {
            'SLACK_TOKEN': 'xoxb-env-token',
            'SLACK_CHANNELS': json.dumps({'default': {'us-east-1': 'alerts'}}),
            'SLACK_URL': 'https://hooks.slack.com/services',
            'AWS_ACCOUNT_IDS': json.dumps(['111111111111']),
            'VERIFY_SIGNATURES': 'true',
            'API_KEYS': json.dumps(['key1']),
            'ALLOWED_REGIONS': json.dumps(['us-east-1']),
            'ALLOWED_TOPIC_PATTERNS': json.dumps(['^test-.*']),
        }
        with patch.dict(os.environ, env, clear=False):
            config = load_config()
        assert config['slack']['token'] == 'xoxb-env-token'
        assert config['slack']['channels'] == {'default': {'us-east-1': 'alerts'}}
        assert config['slack']['url'] == 'https://hooks.slack.com/services'
        assert config['security']['aws_account_ids'] == ['111111111111']
        assert config['security']['verify_signatures'] is True
        assert config['security']['api_keys'] == ['key1']
        assert config['security']['allowed_regions'] == ['us-east-1']
        assert config['security']['allowed_topic_patterns'] == ['^test-.*']

    def test_load_from_env_vars_minimal(self):
        env = {'SLACK_TOKEN': 'xoxb-minimal'}
        with patch.dict(os.environ, env, clear=False):
            config = load_config()
        assert config['slack']['token'] == 'xoxb-minimal'
        assert config['slack']['channels'] == {}
        assert config['security']['aws_account_ids'] == []
        assert config['security']['verify_signatures'] is False

    def test_load_from_config_file(self):
        yaml_content = yaml.dump({
            'slack': {
                'token': 'xoxb-file-token',
                'channels': {'default': {'us-east-1': 'test'}},
            },
            'security': {
                'aws_account_ids': ['222222222222'],
                'verify_signatures': False,
                'allowed_regions': [],
            },
        })
        with patch.dict(os.environ, {}, clear=True):
            with patch('builtins.open', mock_open(read_data=yaml_content)):
                config = load_config()
        assert config['slack']['token'] == 'xoxb-file-token'

    def test_load_from_file_yaml_error(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch('builtins.open', side_effect=[
                Exception('bad yaml'),
                Exception('bad yaml'),
                FileNotFoundError(),
            ]):
                config = load_config()
        # Should fall back to defaults
        assert config['slack']['token'] == 'not-configured'

    def test_load_default_config(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch('builtins.open', side_effect=FileNotFoundError()):
                config = load_config()
        assert config['slack']['token'] == 'not-configured'
        assert 'default' in config['slack']['channels']


class TestValidateConfig:
    def test_adds_missing_security(self):
        config = {
            'slack': {'token': 'test', 'channels': {}},
        }
        validate_config(config)
        assert 'security' in config
        assert config['security']['verify_signatures'] is False

    def test_adds_missing_slack(self):
        config = {
            'security': {'aws_account_ids': [], 'verify_signatures': False, 'allowed_regions': []},
        }
        validate_config(config)
        assert 'slack' in config
        assert config['slack']['token'] == 'not-configured'

    def test_adds_missing_token(self):
        config = {
            'slack': {'channels': {}},
            'security': {'aws_account_ids': [], 'verify_signatures': False, 'allowed_regions': []},
        }
        validate_config(config)
        assert config['slack']['token'] == 'not-configured'

    def test_adds_missing_channels(self):
        config = {
            'slack': {'token': 'test'},
            'security': {'aws_account_ids': [], 'verify_signatures': False, 'allowed_regions': []},
        }
        validate_config(config)
        assert config['slack']['channels'] == {}

    def test_complete_config_unchanged(self):
        config = {
            'slack': {'token': 'my-token', 'channels': {'default': {'us-east-1': 'ch'}}},
            'security': {'aws_account_ids': ['123'], 'verify_signatures': True, 'allowed_regions': ['us-east-1']},
        }
        validate_config(config)
        assert config['slack']['token'] == 'my-token'
