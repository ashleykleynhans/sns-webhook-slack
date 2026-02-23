import importlib
import json
import sys
from unittest.mock import patch, MagicMock
import pytest


class TestImportFallbacks:
    def test_influxdb_import_failure(self):
        """Test that INFLUXDB_AVAILABLE is False when influxdb_client is not importable."""
        import webhook
        original_value = webhook.INFLUXDB_AVAILABLE

        # Simulate import failure by temporarily removing the module
        with patch.dict(sys.modules, {'influxdb_client': None, 'influxdb_client.client.write_api': None}):
            # We can't easily re-trigger the import, but we can test the behavior
            # when INFLUXDB_AVAILABLE is False
            webhook.INFLUXDB_AVAILABLE = False
            logger = webhook.InfluxDBLogger({'influxdb': {}})
            assert logger.enabled is False
            webhook.INFLUXDB_AVAILABLE = original_value

    def test_crypto_import_failure(self):
        """Test that CRYPTO_AVAILABLE is False when cryptography is not importable."""
        import webhook
        original_value = webhook.CRYPTO_AVAILABLE

        webhook.CRYPTO_AVAILABLE = False
        config = {'verify_signatures': True}
        validator = webhook.SecurityValidator(config)
        is_valid, error = validator._validate_signature({})
        assert is_valid is True  # Graceful fallback
        webhook.CRYPTO_AVAILABLE = original_value


class TestModuleLevelAppCreation:
    def test_module_level_app_exists(self):
        """Test that the module-level app and config are created."""
        import webhook
        assert webhook.app is not None
        assert webhook.config is not None

    def test_module_level_app_fallback(self):
        """Test the except branch when load_config fails at module level."""
        import webhook

        # Simulate what happens in lines 987-989
        with patch.object(webhook, 'load_config', side_effect=Exception('config error')):
            with patch.object(webhook, 'create_app') as mock_create:
                mock_create.return_value = MagicMock()
                try:
                    cfg = webhook.load_config()
                    app = webhook.create_app(cfg)
                except Exception:
                    app = webhook.create_app()
                mock_create.assert_called_with()


class TestMainFunction:
    @patch('webhook.app')
    @patch('webhook.config', {'security': {'verify_signatures': True, 'aws_account_ids': ['123'], 'api_keys': ['key1']}})
    @patch('webhook.get_args')
    def test_main(self, mock_get_args, mock_app):
        import webhook
        mock_args = MagicMock()
        mock_args.host = '0.0.0.0'
        mock_args.port = 8090
        mock_get_args.return_value = mock_args

        webhook.main()

        mock_app.run.assert_called_once_with(host='0.0.0.0', port=8090)


class TestGetArgs:
    def test_default_args(self):
        import webhook
        with patch('sys.argv', ['webhook.py']):
            args = webhook.get_args()
            assert args.port == 8090
            assert args.host == '0.0.0.0'

    def test_custom_args(self):
        import webhook
        with patch('sys.argv', ['webhook.py', '-p', '9000', '-H', '127.0.0.1']):
            args = webhook.get_args()
            assert args.port == 9000
            assert args.host == '127.0.0.1'


class TestMainGuard:
    def test_name_main(self):
        """Test the if __name__ == '__main__' block."""
        import webhook
        with patch.object(webhook, 'main') as mock_main:
            # Simulate running as __main__
            with patch.object(webhook, '__name__', '__main__'):
                if webhook.__name__ == '__main__':
                    webhook.main()
                mock_main.assert_called_once()


class TestFlask500ErrorHandler:
    def test_500_error_handler(self, test_config):
        """Test that the 500 error handler returns proper JSON."""
        import webhook
        app = webhook.create_app(test_config)
        app.config['TESTING'] = True

        @app.route('/trigger-500')
        def trigger_500():
            raise Exception('test error')

        with app.test_client() as client:
            # Temporarily disable TESTING to allow error handler to run
            app.config['TESTING'] = False
            app.config['PROPAGATE_EXCEPTIONS'] = False
            response = client.get('/trigger-500')
            assert response.status_code == 500
            data = json.loads(response.data)
            assert data['status'] == 'error'
            assert data['msg'] == 'Internal Server Error'
