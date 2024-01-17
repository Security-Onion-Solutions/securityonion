from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from sublime import sublime
import json
import unittest


class TestSublimePlatformMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                sublime.main()
                self.assertEqual(mock_stderr.getvalue(), '''usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n''')
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('sublime.sublime.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                sublime.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_checkKeyNonexistent(self):
        conf = {"not_a_key": "abcd12345"}
        with self.assertRaises(SystemExit) as cm:
            sublime.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_buildReqLiveFlow(self):
        conf = {'base_url': 'https://api.platform.sublimesecurity.com', 'api_key': 'abcd12345', 'live_flow': True, 'mailbox_email_address': 'user@test.local', 'message_source_id': 'abcd1234'}
        artifact_value = "abcd1234"
        result = sublime.buildReq(conf, artifact_value)
        self.assertEqual("https://api.platform.sublimesecurity.com/v1/live-flow/raw-messages/analyze", result[0])
        self.assertEqual({'Authorization': 'Bearer abcd12345'}, result[1])

    def test_buildReqNotLiveFlow(self):
        conf = {'base_url': 'https://api.platform.sublimesecurity.com', 'api_key': 'abcd12345', 'live_flow': False, 'mailbox_email_address': 'user@test.local'}
        artifact_value = "abcd1234"
        result = sublime.buildReq(conf, artifact_value)
        self.assertEqual("https://api.platform.sublimesecurity.com/v0/messages/analyze", result[0])
        self.assertEqual({'Authorization': 'Bearer abcd12345'}, result[1])

    def test_prepareResultsRuleResultsMatched(self):
        raw = ''' {
              "rule_results": [{
              "rule": {
                "id": "9147f589-39d5-4dd0-a0ee-00433a6e2632",
                "name": "AnonymousFox Indicators",
                "source": "type.inbound\\nand regex.icontains(sender.email.email, \\"(anonymous|smtp)fox-\\"))\\n",
                "severity": "medium"
              },
              "matched": true,
              "success": true,
              "error": null,
              "external_errors": null,
              "execution_time": 0.000071679
            }]}'''
        results = sublime.prepareResults(json.loads(raw))
        print(results)
        self.assertEqual(results["response"], json.loads(raw)["rule_results"])
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResultsRuleResultsNotMatched(self):
        raw = ''' {
              "rule_results": [{
              "rule": {
                "id": "9147f589-39d5-4dd0-a0ee-00433a6e2632",
                "name": "AnonymousFox Indicators",
                "source": "type.inbound and regex.icontains(.value, \\"(anonymous|smtp)fox-\\"))\\n",
                "severity": "medium"
              },
              "matched": false,
              "success": true,
              "error": null,
              "external_errors": null,
              "execution_time": 0.000071679
            }]}'''
        results = sublime.prepareResults(json.loads(raw))
        print(results)
        self.assertEqual(results["response"], "No rules matched.")
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResultsLiveFlowMatched(self):
        raw = '''{
        "canonical_id": "fb8b46e3317ac7d5036c6b21517d363634293c6d4f6bf1b1e67548c80948a1c6",
        "flagged_rules": [
            {
                "actions": null,
                "active": true,
                "active_updated_at": "2023-08-09T14:58:25.669495Z",
                "attack_types": [
                    "Credential Phishing",
                    "Malware/Ransomware"
                ],
                "authors": null,
                "created_at": "2023-08-09 01:00:25.642489+00",
                "created_by_api_request_id": null,
                "created_by_org_id": null,
                "created_by_org_name": null,
                "created_by_user_id": null,
                "created_by_user_name": null,
                "description": "Recursively scans files and archives to detect HTML smuggling techniques.\\n",
                "detection_methods": [
                    "Archive analysis",
                    "File analysis",
                    "HTML analysis",
                    "Javascript analysis"
                ],
                "exclusion_mql": null,
                "false_positives": null,
                "feed_external_rule_id": "0b0fed36-735a-50f1-bf10-6673237a4623",
                "feed_id": "4e5d7da3-d566-4910-a613-f00709702240",
                "full_type": "detection_rule",
                "id": "537bf73d-a4f0-4389-b2a1-272192efa0d5",
                "immutable": true,
                "internal_type": null,
                "label": null,
                "maturity": null,
                "name": "Attachment: HTML smuggling with unescape",
                "org_id": "dac92af8-2bd6-4861-9ee1-a04e713e3ae2",
                "references": [
                    "https://www.microsoft.com/security/blog/2021/11/11/html-smuggling-surges-highly-evasive-loader"
                ],
                "severity": "high",
                "source_md5": "b68388617d78ccc20075ca8fffc7e3f8",
                "tactics_and_techniques": [
                    "Evasion",
                    "HTML smuggling",
                    "Scripting"
                ],
                "tags": null,
                "type": "detection",
                "updated_at": "2023-11-01 15:25:47.212056+00",
                "user_provided_tags": [

                ]
            }
        ],
        "message_id": "0071b1ac-d7ca-4e37-91c5-068a96b9dda8",
        "raw_message_id": "1dc90473-b028-4754-942c-476cfb1ca2ff"
        }'''

        results = sublime.prepareResults(json.loads(raw))
        print(results)
        self.assertEqual(results["response"], json.loads(raw))
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResultsLiveFlowNotMatched(self):
        raw = '''{
        "canonical_id": "092459fa0d9edd5d8e2d0ccf3af50120c63ec58717a8cfdeb15854706940346f",
        "flagged_rules": null,
        "message_id": "1e8693b4-bf44-4cb9-ac9a-85fc2a99eeb8",
        "raw_message_id": "5d2f03c2-86e1-47d8-81ae-620ecb5c6553"
        }'''

        results = sublime.prepareResults(json.loads(raw))
        self.assertEqual(results["response"], json.loads(raw))
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            url = "https://api.platform.sublimesecurity.com/v1/live-flow/raw-messages/analyze"
            headers = {'Authorization': 'Bearer abcd12345'}
            data = {"create_mailbox": True, "mailbox_email_address": "user@test.local", "message_source_id": "abcd1234", "raw_message": "abcd1234"}
            url = "https://api.platform.sublimesecurity.com/v1/live-flow/raw-messages/analyze"
            response = sublime.sendReq(url=url, headers=headers, data=data)
            mock.assert_called_once_with('POST', url=url, headers=headers, data=json.dumps(data))
            self.assertIsNotNone(response)

    def test_analyze(self):
        output = '{"message_id":"abcd1234","raw_message_id":"abcd1234","canonical_id":"abcd1234","flagged_rules":null}'
        artifactInput = '{"value":"RnJvbTogQWxpY2UgPGFsaWNlQGV4YW1wbGUuY29tPgpUbzogQm9iIDxib2JA","artifactType":"eml"}'
        conf = {'base_url': 'https://api.platform.sublimesecurity.com', 'api_key': 'abcd12345', 'live_flow': False, 'mailbox_email_address': 'user@test.local'}
        with patch('sublime.sublime.sendReq', new=MagicMock(return_value=json.loads(output))) as mock:
            results = sublime.analyze(conf, artifactInput)
            print(results)
            self.assertEqual(results["summary"], "harmless")
            mock.assert_called_once()
