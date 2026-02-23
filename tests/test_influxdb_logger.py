from unittest.mock import patch, MagicMock
import pytest
from webhook import InfluxDBLogger


@pytest.fixture
def enabled_config():
    return {
        'influxdb': {
            'prod': {
                'url': 'http://localhost:8086',
                'token': 'test-token',
                'org': 'TestOrg',
                'bucket': 'TestBucket',
            },
        },
        'environments': {
            'us-east-1': 'prod',
        },
    }


@pytest.fixture
def disabled_config():
    return {'slack': {'token': 'test'}}


class TestInfluxDBLoggerInit:
    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_enabled(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        assert logger.enabled is True

    @patch('webhook.INFLUXDB_AVAILABLE', False)
    def test_disabled_no_library(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        assert logger.enabled is False

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_disabled_no_config(self, disabled_config):
        logger = InfluxDBLogger(disabled_config)
        assert logger.enabled is False


class TestExtractRegion:
    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_valid_az(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        assert logger._extract_region('us-east-1a') == 'us-east-1'

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_valid_az_longer(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        assert logger._extract_region('eu-west-2c') == 'eu-west-2'

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_invalid_az(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        assert logger._extract_region('invalid') is None

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_empty_string(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        assert logger._extract_region('') is None


class TestExtractCapacityChanges:
    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_increasing(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        before, after = logger._extract_capacity_changes(
            'increasing the capacity from 2 to 4'
        )
        assert before == 2
        assert after == 4

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_decreasing(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        before, after = logger._extract_capacity_changes(
            'shrinking the capacity from 4 to 2'
        )
        assert before == 4
        assert after == 2

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_no_match(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        before, after = logger._extract_capacity_changes('some other cause')
        assert before == 0
        assert after == 0


class TestLogAutoscalingEvent:
    @patch('webhook.INFLUXDB_AVAILABLE', False)
    def test_disabled(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        # Should return without doing anything
        logger.log_autoscaling_event({})

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_no_region(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        # No AvailabilityZone -> no region -> early return
        logger.log_autoscaling_event({})

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_region_not_in_environments(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        logger.log_autoscaling_event({'AvailabilityZone': 'eu-west-1a'})

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_no_capacity_changes(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        msg = {
            'AvailabilityZone': 'us-east-1a',
            'Cause': 'no capacity info here',
        }
        logger.log_autoscaling_event(msg)

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_successful_logging(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        msg = {
            'AvailabilityZone': 'us-east-1a',
            'Cause': 'increasing the capacity from 1 to 2',
            'AutoScalingGroupName': 'myapp-prod-asg',
        }
        with patch.object(logger, '_write_to_influxdb') as mock_write:
            logger.log_autoscaling_event(msg)
            mock_write.assert_called_once_with(msg, 'us-east-1', 1, 2)

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    def test_exception_handling(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        msg = {
            'AvailabilityZone': 'us-east-1a',
            'Cause': 'increasing the capacity from 1 to 2',
            'AutoScalingGroupName': 'myapp-prod-asg',
        }
        with patch.object(logger, '_write_to_influxdb', side_effect=Exception('db error')):
            # Should not raise
            logger.log_autoscaling_event(msg)


class TestWriteToInfluxDB:
    @patch('webhook.INFLUXDB_AVAILABLE', False)
    def test_influxdb_not_available(self, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        logger.enabled = True  # Force enabled for this test
        logger._write_to_influxdb(
            {'AutoScalingGroupName': 'app-asg', 'AvailabilityZone': 'us-east-1a'},
            'us-east-1', 1, 2
        )

    @patch('webhook.INFLUXDB_AVAILABLE', True)
    @patch('webhook.InfluxDBClient')
    @patch('webhook.Point')
    def test_writes_to_influxdb(self, mock_point_cls, mock_client_cls, enabled_config):
        logger = InfluxDBLogger(enabled_config)
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_write_api = MagicMock()
        mock_client.write_api.return_value = mock_write_api

        mock_point = MagicMock()
        mock_point_cls.return_value = mock_point
        mock_point.tag.return_value = mock_point
        mock_point.field.return_value = mock_point

        msg = {
            'AutoScalingGroupName': 'myapp-prod-asg',
            'AvailabilityZone': 'us-east-1a',
        }
        logger._write_to_influxdb(msg, 'us-east-1', 1, 2)

        mock_client_cls.assert_called_once()
        mock_write_api.write.assert_called_once()
        mock_client.close.assert_called_once()
