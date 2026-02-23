import json
from unittest.mock import patch
import pytest
from flask import Flask
from webhook import (
    _parse_sns_message,
    _determine_notification_type,
    _format_message,
    _should_skip_notification,
    _get_slack_channel,
    require_api_key,
    NOTIFICATION_TYPES,
)


class TestParseSnsMessage:
    def test_valid_json(self):
        payload = {'Message': json.dumps({'key': 'value'})}
        result = _parse_sns_message(payload)
        assert result == {'key': 'value'}

    def test_invalid_json(self):
        payload = {'Message': 'not json'}
        result = _parse_sns_message(payload)
        assert result is None

    def test_missing_message_key(self):
        result = _parse_sns_message({})
        assert result is None


class TestDetermineNotificationType:
    def test_autoscaling_launch(self):
        msg = {'Event': 'autoscaling:EC2_INSTANCE_LAUNCH'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.AUTOSCALING
        assert color == 'good'

    def test_autoscaling_terminate(self):
        msg = {'Event': 'autoscaling:EC2_INSTANCE_TERMINATE'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.AUTOSCALING
        assert color == 'danger'

    @patch('webhook.COLORS', {'custom:EVENT': 'warning'})
    def test_event_in_colors_not_autoscaling(self):
        msg = {'Event': 'custom:EVENT'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.DEFAULT
        assert color == 'warning'

    def test_support_case(self):
        msg = {'detail-type': 'Support Case Update'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.SUPPORT
        assert color == 'good'

    def test_savings_plans(self):
        msg = {'detail-type': 'Savings Plans State Change Alert'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.SAVINGS_PLANS
        assert color == 'good'

    def test_health_event(self):
        msg = {
            'detail-type': 'AWS Health Event',
            'detail': {'eventTypeCategory': 'scheduledChange'},
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.HEALTH
        assert color == 'good'

    def test_health_event_issue(self):
        msg = {
            'detail-type': 'AWS Health Event',
            'detail': {'eventTypeCategory': 'issue'},
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.HEALTH
        assert color == 'danger'

    def test_acm_certificate(self):
        msg = {'detail-type': 'ACM Certificate Approaching Expiration'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.ACM
        assert color == 'warning'

    def test_acm_certificate_no_warning(self):
        msg = {'detail-type': 'ACM Certificate Issued'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.ACM
        assert color == 'good'

    def test_rekognition_eol(self):
        msg = {'detail-type': 'Amazon Rekognition End of Life Notice'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.REKOGNITION
        assert color == 'warning'

    def test_rekognition_normal(self):
        msg = {'detail-type': 'Rekognition Model Update'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.REKOGNITION
        assert color == 'good'

    def test_security_hub_critical(self):
        msg = {
            'detail-type': 'Security Hub Findings - Imported',
            'detail': {
                'findings': [{'Severity': {'Label': 'CRITICAL'}}],
            },
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.SECURITY_HUB
        assert color == 'danger'

    def test_security_hub_medium(self):
        msg = {
            'detail-type': 'Security Hub Findings - Imported',
            'detail': {
                'findings': [{'Severity': {'Label': 'MEDIUM'}}],
            },
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.SECURITY_HUB
        assert color == 'warning'

    def test_security_hub_low(self):
        msg = {
            'detail-type': 'Security Hub Findings - Imported',
            'detail': {
                'findings': [{'Severity': {'Label': 'LOW'}}],
            },
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.SECURITY_HUB
        assert color == 'good'

    def test_trusted_advisor_error(self):
        msg = {
            'detail-type': 'Trusted Advisor Check',
            'detail': {'status': 'error'},
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.TRUSTED_ADVISOR
        assert color == 'danger'

    def test_trusted_advisor_warning(self):
        msg = {
            'detail-type': 'Trusted Advisor Check',
            'detail': {'status': 'warning'},
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.TRUSTED_ADVISOR
        assert color == 'warning'

    def test_trusted_advisor_ok(self):
        msg = {
            'detail-type': 'Trusted Advisor Check',
            'detail': {'status': 'ok'},
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.TRUSTED_ADVISOR
        assert color == 'good'

    def test_config_non_compliant(self):
        msg = {
            'detail-type': 'Config Rules Compliance Change',
            'detail': {
                'newEvaluationResult': {'complianceType': 'NON_COMPLIANT'},
            },
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.CONFIG
        assert color == 'danger'

    def test_config_compliant(self):
        msg = {
            'detail-type': 'Config Rules Compliance Change',
            'detail': {
                'newEvaluationResult': {'complianceType': 'COMPLIANT'},
            },
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.CONFIG
        assert color == 'good'

    def test_cloudwatch_alarm(self):
        msg = {
            'detail-type': 'CloudWatch Alarm State Change',
            'detail': {'state': {'value': 'ALARM'}},
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.CLOUDWATCH
        assert color == 'danger'

    def test_cloudwatch_insufficient_data(self):
        msg = {
            'detail-type': 'CloudWatch Alarm State Change',
            'detail': {'state': {'value': 'INSUFFICIENT_DATA'}},
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.CLOUDWATCH
        assert color == 'warning'

    def test_cloudwatch_ok(self):
        msg = {
            'detail-type': 'CloudWatch Alarm State Change',
            'detail': {'state': {'value': 'OK'}},
        }
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.CLOUDWATCH
        assert color == 'good'

    def test_aws_service_generic(self):
        msg = {'detail-type': 'AWS API Call via CloudTrail'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.AWS_SERVICE
        assert color == 'good'

    def test_default_no_detail_type(self):
        msg = {'some_key': 'some_value'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.DEFAULT
        assert color == 'good'

    def test_default_unrecognized_detail_type(self):
        msg = {'detail-type': 'Something Unknown'}
        ntype, color = _determine_notification_type(msg)
        assert ntype == NOTIFICATION_TYPES.DEFAULT
        assert color == 'good'


class TestFormatMessage:
    def test_health_event(self):
        msg = {
            'account': '123456789012',
            'region': 'us-east-1',
            'resources': ['i-abc123'],
            'detail': {
                'service': 'EC2',
                'eventTypeCode': 'AWS_EC2_MAINTENANCE',
                'eventTypeCategory': 'scheduledChange',
                'startTime': '2026-01-01',
                'endTime': '2026-01-02',
                'eventDescription': [
                    {'language': 'en_US', 'latestDescription': 'Line1\\nLine2'},
                    {'language': 'ja_JP', 'latestDescription': 'ignored'},
                ],
                'affectedEntities': [
                    {'entityValue': 'i-abc123'},
                ],
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.HEALTH)
        assert '**Account:** 123456789012' in result
        assert '**Region:** us-east-1' in result
        assert '**Resources:** i-abc123' in result
        assert '**Service:** EC2' in result
        assert 'Line1\nLine2' in result
        assert '**Affected Entities:**' in result
        assert 'i-abc123' in result

    def test_health_event_no_resources(self):
        msg = {
            'account': '123456789012',
            'region': 'us-east-1',
            'detail': {
                'service': 'EC2',
                'eventTypeCode': 'test',
                'eventTypeCategory': 'test',
                'startTime': 'now',
                'endTime': 'later',
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.HEALTH)
        assert '**Resources:**' not in result
        assert '**Affected Entities:**' not in result

    def test_health_event_non_english_only(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'detail': {
                'service': 'EC2',
                'eventTypeCode': 'test',
                'eventTypeCategory': 'test',
                'startTime': 'now',
                'endTime': 'later',
                'eventDescription': [
                    {'language': 'ja_JP', 'latestDescription': 'Japanese only'},
                ],
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.HEALTH)
        assert 'Japanese only' not in result

    def test_autoscaling(self):
        msg = {
            'Event': 'autoscaling:EC2_INSTANCE_LAUNCH',
            'AutoScalingGroupName': 'my-asg',
            'Details': {'Availability Zone': 'us-east-1a'},
        }
        result = _format_message(msg, NOTIFICATION_TYPES.AUTOSCALING)
        assert '**Event:**' in result
        assert '**AvailabilityZone:**' in result
        assert 'my-asg' in result

    def test_autoscaling_without_details(self):
        msg = {
            'Event': 'autoscaling:EC2_INSTANCE_LAUNCH',
            'AutoScalingGroupName': 'my-asg',
        }
        result = _format_message(msg, NOTIFICATION_TYPES.AUTOSCALING)
        assert 'my-asg' in result

    def test_acm(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': '2026-01-01',
            'detail': {
                'DaysToExpiry': 30,
                'CommonName': 'example.com',
                'certificateArn': 'arn:aws:acm:us-east-1:123:certificate/abc',
                'Action': 'RENEWAL',
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.ACM)
        assert '**Days to Expiry:** 30' in result
        assert '**Certificate:** example.com' in result
        assert '**Certificate ARN:**' in result
        assert '**Action:** RENEWAL' in result

    def test_acm_minimal(self):
        msg = {'account': '123', 'region': 'us-east-1', 'time': 'now', 'detail': {}}
        result = _format_message(msg, NOTIFICATION_TYPES.ACM)
        assert '**Account:** 123' in result
        assert 'Days to Expiry' not in result

    def test_rekognition(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': '2026-01-01',
            'detail': {'model': 'v1', 'status': 'deprecated'},
        }
        result = _format_message(msg, NOTIFICATION_TYPES.REKOGNITION)
        assert '**model:** v1' in result
        assert '**status:** deprecated' in result

    def test_security_hub(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': '2026-01-01',
            'detail': {
                'findings': [
                    {
                        'Title': 'Finding 1',
                        'Severity': {'Label': 'HIGH'},
                        'Types': ['Software/CVE'],
                        'Description': 'Bad thing',
                        'Resources': [{'Id': 'arn:resource1'}, {'Id': 'arn:resource2'}],
                    },
                ],
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.SECURITY_HUB)
        assert '**Title:** Finding 1' in result
        assert '**Severity:** HIGH' in result
        assert '**Type:** Software/CVE' in result
        assert '**Description:** Bad thing' in result
        assert 'arn:resource1' in result

    def test_security_hub_no_findings(self):
        msg = {'account': '123', 'region': 'us-east-1', 'time': 'now', 'detail': {}}
        result = _format_message(msg, NOTIFICATION_TYPES.SECURITY_HUB)
        assert '**Account:** 123' in result

    def test_security_hub_finding_no_types(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': 'now',
            'detail': {
                'findings': [
                    {'Title': 'F1', 'Severity': {'Label': 'LOW'}, 'Description': 'desc'},
                ],
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.SECURITY_HUB)
        assert '**Type:** N/A' in result

    def test_security_hub_finding_empty_types(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': 'now',
            'detail': {
                'findings': [
                    {'Title': 'F1', 'Severity': {'Label': 'LOW'}, 'Types': [], 'Description': 'desc'},
                ],
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.SECURITY_HUB)
        assert '**Type:** N/A' in result

    def test_trusted_advisor(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': '2026-01-01',
            'detail': {
                'check-name': 'S3 Permissions',
                'status': 'warning',
                'resource_id': 'my-bucket',
                'extra_field': 'extra_value',
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.TRUSTED_ADVISOR)
        assert '**Check Name:** S3 Permissions' in result
        assert '**Status:** warning' in result
        assert '**Resource ID:** my-bucket' in result
        assert '**extra_field:** extra_value' in result

    def test_config(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': '2026-01-01',
            'detail': {
                'configRuleName': 'my-rule',
                'newEvaluationResult': {
                    'complianceType': 'NON_COMPLIANT',
                    'evaluationResultIdentifier': {
                        'evaluationResultQualifier': {
                            'resourceType': 'AWS::S3::Bucket',
                            'resourceId': 'my-bucket',
                        },
                    },
                },
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.CONFIG)
        assert '**Config Rule:** my-rule' in result
        assert '**Compliance Type:** NON_COMPLIANT' in result
        assert '**Resource Type:** AWS::S3::Bucket' in result
        assert '**Resource ID:** my-bucket' in result

    def test_config_no_evaluation_result(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': 'now',
            'detail': {'configRuleName': 'rule'},
        }
        result = _format_message(msg, NOTIFICATION_TYPES.CONFIG)
        assert '**Config Rule:** rule' in result

    def test_cloudwatch(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': '2026-01-01',
            'detail': {
                'alarmName': 'HighCPU',
                'state': {'value': 'ALARM', 'reason': 'Threshold exceeded'},
                'configuration': {'description': 'CPU is too high'},
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.CLOUDWATCH)
        assert '**Alarm Name:** HighCPU' in result
        assert '**State:** ALARM' in result
        assert '**Reason:** Threshold exceeded' in result
        assert '**Description:** CPU is too high' in result

    def test_cloudwatch_no_description(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': 'now',
            'detail': {
                'alarmName': 'Test',
                'state': {'value': 'OK', 'reason': 'ok'},
                'configuration': {},
            },
        }
        result = _format_message(msg, NOTIFICATION_TYPES.CLOUDWATCH)
        assert '**Description:**' not in result

    def test_aws_service(self):
        msg = {
            'account': '123',
            'region': 'us-east-1',
            'time': '2026-01-01',
            'source': 'aws.ec2',
            'detail': {'instance-id': 'i-123', 'state': 'running'},
        }
        result = _format_message(msg, NOTIFICATION_TYPES.AWS_SERVICE)
        assert '**Source:** aws.ec2' in result
        assert '**instance-id:** i-123' in result

    def test_default_format(self):
        msg = {'key1': 'value1', 'key2': 'value2'}
        result = _format_message(msg, NOTIFICATION_TYPES.DEFAULT)
        assert 'key1: value1' in result
        assert 'key2: value2' in result

    def test_support_format(self):
        # Support uses default format (falls through to else)
        msg = {'case-id': '123', 'subject': 'Help'}
        result = _format_message(msg, NOTIFICATION_TYPES.SUPPORT)
        assert 'case-id: 123' in result

    def test_savings_plans_format(self):
        # Savings plans uses default format (falls through to else)
        msg = {'plan-id': 'sp-123', 'state': 'active'}
        result = _format_message(msg, NOTIFICATION_TYPES.SAVINGS_PLANS)
        assert 'plan-id: sp-123' in result


class TestShouldSkipNotification:
    def test_excluded_event(self):
        msg = {'Event': 'autoscaling:TEST_NOTIFICATION'}
        assert _should_skip_notification(msg) is True

    def test_non_excluded_event(self):
        msg = {'Event': 'autoscaling:EC2_INSTANCE_LAUNCH'}
        assert _should_skip_notification(msg) is False

    def test_no_event_key(self):
        msg = {'detail-type': 'Some Event'}
        assert _should_skip_notification(msg) is False


class TestGetSlackChannel:
    def test_exact_match(self):
        config = {
            'slack': {
                'channels': {
                    'health': {'us-east-1': 'health-channel'},
                    'default': {'us-east-1': 'default-channel'},
                },
            },
        }
        result = _get_slack_channel(config, 'health', 'us-east-1')
        assert result == 'health-channel'

    def test_type_match_region_fallback(self):
        config = {
            'slack': {
                'channels': {
                    'health': {'us-west-2': 'health-west'},
                    'default': {'us-east-1': 'default-channel'},
                },
            },
        }
        result = _get_slack_channel(config, 'health', 'us-east-1')
        assert result == 'health-west'

    def test_default_channel_exact_region(self):
        config = {
            'slack': {
                'channels': {
                    'default': {'us-east-1': 'default-east'},
                },
            },
        }
        result = _get_slack_channel(config, 'health', 'us-east-1')
        assert result == 'default-east'

    def test_default_channel_region_fallback(self):
        config = {
            'slack': {
                'channels': {
                    'default': {'us-west-2': 'default-west'},
                },
            },
        }
        result = _get_slack_channel(config, 'health', 'us-east-1')
        assert result == 'default-west'

    def test_ultimate_fallback(self):
        config = {'slack': {'channels': {}}}
        result = _get_slack_channel(config, 'health', 'us-east-1')
        assert result == 'notifications'

    def test_empty_type_channels(self):
        config = {
            'slack': {
                'channels': {
                    'health': {},
                    'default': {'us-east-1': 'default-ch'},
                },
            },
        }
        result = _get_slack_channel(config, 'health', 'us-east-1')
        assert result == 'default-ch'

    def test_empty_default_channels(self):
        config = {
            'slack': {
                'channels': {
                    'default': {},
                },
            },
        }
        result = _get_slack_channel(config, 'health', 'us-east-1')
        assert result == 'notifications'


class TestRequireApiKey:
    def test_no_api_keys_configured(self, app):
        """When no API keys configured, all requests pass through."""
        config = {'security': {'api_keys': []}}
        test_app = Flask(__name__)

        @test_app.route('/test', methods=['POST'])
        @require_api_key(config)
        def test_endpoint():
            return 'ok'

        with test_app.test_client() as client:
            response = client.post('/test')
            assert response.status_code == 200

    def test_valid_api_key(self):
        config = {'security': {'api_keys': ['valid-key']}}
        test_app = Flask(__name__)

        @test_app.route('/test', methods=['POST'])
        @require_api_key(config)
        def test_endpoint():
            return 'ok'

        with test_app.test_client() as client:
            response = client.post('/test', headers={'X-API-Key': 'valid-key'})
            assert response.status_code == 200

    def test_invalid_api_key(self):
        config = {'security': {'api_keys': ['valid-key']}}
        test_app = Flask(__name__)

        @test_app.route('/test', methods=['POST'])
        @require_api_key(config)
        def test_endpoint():
            return 'ok'

        with test_app.test_client() as client:
            response = client.post('/test', headers={'X-API-Key': 'wrong-key'})
            assert response.status_code == 401

    def test_missing_api_key(self):
        config = {'security': {'api_keys': ['valid-key']}}
        test_app = Flask(__name__)

        @test_app.route('/test', methods=['POST'])
        @require_api_key(config)
        def test_endpoint():
            return 'ok'

        with test_app.test_client() as client:
            response = client.post('/test')
            assert response.status_code == 401
