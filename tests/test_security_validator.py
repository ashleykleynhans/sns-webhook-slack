from unittest.mock import patch, MagicMock
import pytest
import webhook
from webhook import SecurityValidator


@pytest.fixture
def security_config():
    return {
        'aws_account_ids': ['123456789012'],
        'allowed_regions': ['us-east-1', 'us-east-2'],
        'verify_signatures': False,
        'api_keys': [],
        'allowed_topic_patterns': [],
    }


@pytest.fixture
def validator(security_config):
    return SecurityValidator(security_config)


class TestValidateTopicArn:
    def test_valid_arn(self, validator):
        is_valid, error = validator._validate_topic_arn(
            'arn:aws:sns:us-east-1:123456789012:my-topic'
        )
        assert is_valid is True
        assert error == ''

    def test_invalid_arn_format_too_few_parts(self, validator):
        is_valid, error = validator._validate_topic_arn('arn:aws:sns')
        assert is_valid is False
        assert error == 'Invalid ARN format'

    def test_not_sns_arn(self, validator):
        is_valid, error = validator._validate_topic_arn(
            'arn:aws:sqs:us-east-1:123456789012:my-queue'
        )
        assert is_valid is False
        assert error == 'Not an SNS ARN'

    def test_invalid_arn_prefix(self, validator):
        is_valid, error = validator._validate_topic_arn(
            'foo:aws:sns:us-east-1:123456789012:my-topic'
        )
        assert is_valid is False
        assert error == 'Not an SNS ARN'

    def test_unauthorized_account(self, validator):
        is_valid, error = validator._validate_topic_arn(
            'arn:aws:sns:us-east-1:999999999999:my-topic'
        )
        assert is_valid is False
        assert 'Unauthorized AWS account' in error

    def test_unauthorized_region(self, validator):
        is_valid, error = validator._validate_topic_arn(
            'arn:aws:sns:eu-west-1:123456789012:my-topic'
        )
        assert is_valid is False
        assert 'Unauthorized region' in error

    def test_empty_allowed_accounts_allows_all(self):
        config = {
            'aws_account_ids': [],
            'allowed_regions': [],
            'verify_signatures': False,
        }
        validator = SecurityValidator(config)
        is_valid, error = validator._validate_topic_arn(
            'arn:aws:sns:eu-west-1:999999999999:any-topic'
        )
        assert is_valid is True

    def test_allowed_topic_patterns_match(self):
        config = {
            'aws_account_ids': [],
            'allowed_regions': [],
            'verify_signatures': False,
            'allowed_topic_patterns': [r'^my-.*', r'^test-.*'],
        }
        validator = SecurityValidator(config)
        is_valid, error = validator._validate_topic_arn(
            'arn:aws:sns:us-east-1:123456789012:my-topic'
        )
        assert is_valid is True

    def test_allowed_topic_patterns_no_match(self):
        config = {
            'aws_account_ids': [],
            'allowed_regions': [],
            'verify_signatures': False,
            'allowed_topic_patterns': [r'^allowed-.*'],
        }
        validator = SecurityValidator(config)
        is_valid, error = validator._validate_topic_arn(
            'arn:aws:sns:us-east-1:123456789012:denied-topic'
        )
        assert is_valid is False
        assert "doesn't match allowed patterns" in error

    def test_exception_handling(self, validator):
        # Pass a non-string to trigger exception
        is_valid, error = validator._validate_topic_arn(None)
        assert is_valid is False
        assert 'Failed to parse Topic ARN' in error


class TestValidateRequest:
    def test_valid_request(self, validator):
        payload = {'TopicArn': 'arn:aws:sns:us-east-1:123456789012:my-topic'}
        is_valid, error = validator.validate_request(payload)
        assert is_valid is True

    def test_no_topic_arn(self, validator):
        payload = {'Type': 'Notification'}
        is_valid, error = validator.validate_request(payload)
        assert is_valid is True

    def test_invalid_topic_arn(self, validator):
        payload = {'TopicArn': 'arn:aws:sqs:us-east-1:123456789012:bad'}
        is_valid, error = validator.validate_request(payload)
        assert is_valid is False

    @patch.object(SecurityValidator, '_validate_signature', return_value=(True, ''))
    def test_signature_validation_passes(self, mock_sig):
        config = {
            'aws_account_ids': [],
            'allowed_regions': [],
            'verify_signatures': True,
        }
        validator = SecurityValidator(config)
        with patch('webhook.CRYPTO_AVAILABLE', True):
            payload = {'TopicArn': 'arn:aws:sns:us-east-1:123456789012:topic'}
            is_valid, error = validator.validate_request(payload)
            assert is_valid is True
            assert error == ''

    @patch.object(SecurityValidator, '_validate_signature', return_value=(False, 'bad sig'))
    def test_signature_validation_called_when_enabled(self, mock_sig):
        config = {
            'aws_account_ids': [],
            'allowed_regions': [],
            'verify_signatures': True,
        }
        validator = SecurityValidator(config)
        with patch('webhook.CRYPTO_AVAILABLE', True):
            payload = {'TopicArn': 'arn:aws:sns:us-east-1:123456789012:topic'}
            is_valid, error = validator.validate_request(payload)
            assert is_valid is False
            assert error == 'bad sig'

    def test_signature_validation_skipped_when_disabled(self, validator):
        payload = {
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:topic',
            'Signature': 'dGVzdA==',
            'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/cert.pem',
        }
        is_valid, error = validator.validate_request(payload)
        assert is_valid is True


class TestValidateSignature:
    def test_crypto_not_available(self):
        config = {'verify_signatures': True}
        validator = SecurityValidator(config)
        with patch('webhook.CRYPTO_AVAILABLE', False):
            is_valid, error = validator._validate_signature({})
            assert is_valid is True

    def test_verify_signatures_disabled(self):
        config = {'verify_signatures': False}
        validator = SecurityValidator(config)
        with patch('webhook.CRYPTO_AVAILABLE', True):
            is_valid, error = validator._validate_signature({})
            assert is_valid is True

    def test_missing_signature_fields_with_verify_enabled(self):
        config = {'verify_signatures': True}
        validator = SecurityValidator(config)
        with patch('webhook.CRYPTO_AVAILABLE', True):
            is_valid, error = validator._validate_signature({'Type': 'Notification'})
            assert is_valid is False
            assert error == 'Missing signature fields'

    def test_invalid_cert_url(self):
        config = {'verify_signatures': True}
        validator = SecurityValidator(config)
        with patch('webhook.CRYPTO_AVAILABLE', True):
            payload = {
                'SigningCertURL': 'http://evil.com/cert.pem',
                'Signature': 'dGVzdA==',
            }
            is_valid, error = validator._validate_signature(payload)
            assert is_valid is False
            assert 'Invalid certificate URL' in error

    def test_failed_certificate_retrieval(self):
        config = {'verify_signatures': True}
        validator = SecurityValidator(config)
        with patch('webhook.CRYPTO_AVAILABLE', True):
            with patch.object(validator, '_get_certificate', return_value=None):
                payload = {
                    'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/cert.pem',
                    'Signature': 'dGVzdA==',
                }
                is_valid, error = validator._validate_signature(payload)
                assert is_valid is False
                assert error == 'Failed to retrieve certificate'

    def test_valid_rsa_signature(self):
        config = {'verify_signatures': True}
        validator = SecurityValidator(config)

        mock_public_key = MagicMock(spec=webhook.rsa.RSAPublicKey)
        mock_public_key.verify.return_value = None  # No exception = valid

        mock_cert = MagicMock()
        mock_cert.public_key.return_value = mock_public_key

        with patch('webhook.CRYPTO_AVAILABLE', True):
            with patch.object(validator, '_get_certificate', return_value=mock_cert):
                payload = {
                    'Type': 'Notification',
                    'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/cert.pem',
                    'Signature': 'dGVzdA==',
                    'Message': 'test',
                    'MessageId': '123',
                    'Timestamp': '2026-01-01T00:00:00Z',
                    'TopicArn': 'arn:aws:sns:us-east-1:123456789012:topic',
                }
                is_valid, error = validator._validate_signature(payload)
                assert is_valid is True

    def test_invalid_rsa_signature(self):
        config = {'verify_signatures': True}
        validator = SecurityValidator(config)

        mock_public_key = MagicMock(spec=webhook.rsa.RSAPublicKey)
        mock_public_key.verify.side_effect = Exception('bad signature')

        mock_cert = MagicMock()
        mock_cert.public_key.return_value = mock_public_key

        with patch('webhook.CRYPTO_AVAILABLE', True):
            with patch.object(validator, '_get_certificate', return_value=mock_cert):
                payload = {
                    'Type': 'Notification',
                    'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/cert.pem',
                    'Signature': 'dGVzdA==',
                    'Message': 'test',
                    'MessageId': '123',
                    'Timestamp': '2026-01-01T00:00:00Z',
                    'TopicArn': 'arn:aws:sns:us-east-1:123456789012:topic',
                }
                is_valid, error = validator._validate_signature(payload)
                assert is_valid is False
                assert error == 'Invalid signature'

    def test_unsupported_key_type(self):
        config = {'verify_signatures': True}
        validator = SecurityValidator(config)

        mock_public_key = MagicMock()  # Not an RSAPublicKey
        mock_cert = MagicMock()
        mock_cert.public_key.return_value = mock_public_key

        with patch('webhook.CRYPTO_AVAILABLE', True):
            with patch.object(validator, '_get_certificate', return_value=mock_cert):
                with patch('webhook.isinstance', side_effect=lambda obj, cls: False, create=True):
                    payload = {
                        'Type': 'Notification',
                        'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/cert.pem',
                        'Signature': 'dGVzdA==',
                        'Message': 'test',
                        'MessageId': '123',
                        'Timestamp': '2026-01-01T00:00:00Z',
                        'TopicArn': 'arn:aws:sns:us-east-1:123456789012:topic',
                    }
                    is_valid, error = validator._validate_signature(payload)
                    assert is_valid is False
                    # Could be "Unsupported key type" or "Signature validation failed"
                    assert not is_valid

    def test_general_exception(self):
        config = {'verify_signatures': True}
        validator = SecurityValidator(config)
        with patch('webhook.CRYPTO_AVAILABLE', True):
            with patch.object(validator, '_is_valid_cert_url', side_effect=Exception('boom')):
                payload = {
                    'SigningCertURL': 'https://sns.us-east-1.amazonaws.com/cert.pem',
                    'Signature': 'dGVzdA==',
                }
                is_valid, error = validator._validate_signature(payload)
                assert is_valid is False
                assert 'Signature validation failed' in error


class TestIsValidCertUrl:
    def test_valid_url(self, validator):
        assert validator._is_valid_cert_url(
            'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem'
        ) is True

    def test_http_scheme(self, validator):
        assert validator._is_valid_cert_url(
            'http://sns.us-east-1.amazonaws.com/cert.pem'
        ) is False

    def test_invalid_domain(self, validator):
        assert validator._is_valid_cert_url(
            'https://evil.com/cert.pem'
        ) is False

    def test_non_pem_extension(self, validator):
        assert validator._is_valid_cert_url(
            'https://sns.us-east-1.amazonaws.com/cert.txt'
        ) is False

    def test_none_url(self, validator):
        assert validator._is_valid_cert_url(None) is False

    @patch('webhook.urlparse', side_effect=ValueError('bad url'))
    def test_exception(self, mock_urlparse, validator):
        assert validator._is_valid_cert_url('https://example.com/cert.pem') is False


class TestGetCertificate:
    def test_cached_certificate(self, validator):
        mock_cert = MagicMock()
        validator.cert_cache['https://example.com/cert.pem'] = mock_cert
        result = validator._get_certificate('https://example.com/cert.pem')
        assert result is mock_cert

    @patch('webhook.CRYPTO_AVAILABLE', False)
    def test_crypto_not_available(self, validator):
        result = validator._get_certificate('https://example.com/cert.pem')
        assert result is None

    @patch('webhook.CRYPTO_AVAILABLE', True)
    @patch('webhook.requests.get')
    @patch('webhook.x509.load_pem_x509_certificate')
    def test_successful_download(self, mock_load, mock_get, validator):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'cert data'
        mock_get.return_value = mock_response

        mock_cert = MagicMock()
        mock_load.return_value = mock_cert

        result = validator._get_certificate('https://sns.us-east-1.amazonaws.com/cert.pem')
        assert result is mock_cert
        assert 'https://sns.us-east-1.amazonaws.com/cert.pem' in validator.cert_cache

    @patch('webhook.CRYPTO_AVAILABLE', True)
    @patch('webhook.requests.get')
    def test_download_failure_status(self, mock_get, validator):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = validator._get_certificate('https://sns.us-east-1.amazonaws.com/cert.pem')
        assert result is None

    @patch('webhook.CRYPTO_AVAILABLE', True)
    @patch('webhook.requests.get', side_effect=Exception('network error'))
    def test_download_exception(self, mock_get, validator):
        result = validator._get_certificate('https://sns.us-east-1.amazonaws.com/cert.pem')
        assert result is None


class TestBuildStringToSign:
    def test_notification_type(self, validator):
        payload = {
            'Type': 'Notification',
            'Message': 'hello',
            'MessageId': '123',
            'Subject': 'Test',
            'Timestamp': '2026-01-01T00:00:00Z',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:topic',
        }
        result = validator._build_string_to_sign(payload)
        assert 'Message\nhello\n' in result
        assert 'Subject\nTest\n' in result
        assert 'SubscribeURL' not in result

    def test_subscription_confirmation_type(self, validator):
        payload = {
            'Type': 'SubscriptionConfirmation',
            'Message': 'confirm',
            'MessageId': '456',
            'SubscribeURL': 'https://example.com/confirm',
            'Token': 'abc',
            'Timestamp': '2026-01-01T00:00:00Z',
            'TopicArn': 'arn:aws:sns:us-east-1:123456789012:topic',
        }
        result = validator._build_string_to_sign(payload)
        assert 'SubscribeURL\nhttps://example.com/confirm\n' in result
        assert 'Token\nabc\n' in result
        assert 'Subject' not in result

    def test_missing_optional_fields(self, validator):
        payload = {
            'Type': 'Notification',
            'Message': 'hello',
            'MessageId': '123',
        }
        result = validator._build_string_to_sign(payload)
        assert 'Message\nhello\n' in result
        assert 'Subject' not in result
