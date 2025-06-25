# Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import requests
import os
import subprocess
import json
from datetime import datetime
import importlib

ds = importlib.import_module('so-detections-backup')

class TestBackupScript(unittest.TestCase):

    def setUp(self):
        self.output_dir = '/nsm/backup/detections/repo'
        self.auth_file_path = '/nsm/backup/detections/repo'
        self.mock_auth_data = 'user = "so_elastic:@Tu_dv_[7SvK7[-JZN39BBlSa;WAyf8rCY+3w~Sntp=7oR9*~34?Csi)a@v?)K*vK4vQAywS"'
        self.auth_credentials = 'so_elastic:@Tu_dv_[7SvK7[-JZN39BBlSa;WAyf8rCY+3w~Sntp=7oR9*~34?Csi)a@v?)K*vK4vQAywS'
        self.auth = requests.auth.HTTPBasicAuth('so_elastic', '@Tu_dv_[7SvK7[-JZN39BBlSa;WAyf8rCY+3w~Sntp=7oR9*~34?Csi)a@v?)K*vK4vQAywS')
        self.mock_detection_hit = {
            "_source": {
                "so_detection": {
                    "publicId": "test_id",
                    "content": "test_content",
                    "language": "suricata"
                }
            }
        }
        self.mock_override_hit = {
            "_source": {
                "so_detection": {
                    "publicId": "test_id",
                    "overrides": [{"key": "value"}],
                    "language": "sigma"
                }
            }
        }

    def assert_file_written(self, mock_file, expected_path, expected_content):
        mock_file.assert_called_once_with(expected_path, 'w')
        mock_file().write.assert_called_once_with(expected_content)

    @patch('builtins.open', new_callable=mock_open, read_data='user = "so_elastic:@Tu_dv_[7SvK7[-JZN39BBlSa;WAyf8rCY+3w~Sntp=7oR9*~34?Csi)a@v?)K*vK4vQAywS"')
    def test_get_auth_credentials(self, mock_file):
        credentials = ds.get_auth_credentials(self.auth_file_path)
        self.assertEqual(credentials, self.auth_credentials)
        mock_file.assert_called_once_with(self.auth_file_path, 'r')

    @patch('requests.get')
    def test_query_elasticsearch(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {'hits': {'hits': []}}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        response = ds.query_elasticsearch(ds.QUERY_DETECTIONS, self.auth)
        
        self.assertEqual(response, {'hits': {'hits': []}})
        mock_get.assert_called_once_with(
            ds.ES_URL,
            headers={"Content-Type": "application/json"},
            data=ds.QUERY_DETECTIONS,
            auth=self.auth,
            verify=False
        )

    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    def test_save_content(self, mock_file, mock_makedirs):
        file_path = ds.save_content(self.mock_detection_hit, self.output_dir, 'subfolder', 'txt')
        expected_path = f'{self.output_dir}/subfolder/test_id.txt'
        self.assertEqual(file_path, expected_path)
        mock_makedirs.assert_called_once_with(f'{self.output_dir}/subfolder', exist_ok=True)
        self.assert_file_written(mock_file, expected_path, 'test_content')

    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    def test_save_overrides(self, mock_file, mock_makedirs):
        file_path = ds.save_overrides(self.mock_override_hit)
        expected_path = f'{self.output_dir}/sigma/overrides/test_id.yaml'
        self.assertEqual(file_path, expected_path)
        mock_makedirs.assert_called_once_with(f'{self.output_dir}/sigma/overrides', exist_ok=True)
        self.assert_file_written(mock_file, expected_path, json.dumps({"key": "value"}))

    @patch('subprocess.run')
    def test_ensure_git_repo(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        
        ds.ensure_git_repo()
        
        mock_run.assert_has_calls([
            call(["git", "config", "--global", "init.defaultBranch", "main"], check=True),
            call(["git", "-C", self.output_dir, "init"], check=True),
            call(["git", "-C", self.output_dir, "remote", "add", "origin", "default"], check=True)
        ])

    @patch('subprocess.run')
    def test_commit_changes(self, mock_run):
        mock_status_result = MagicMock()
        mock_status_result.stdout = "On branch main\nnothing to commit, working tree clean"
        mock_commit_result = MagicMock(returncode=1)
        # Ensure sufficient number of MagicMock instances for each subprocess.run call
        mock_run.side_effect = [mock_status_result, mock_commit_result, MagicMock(returncode=0), MagicMock(returncode=0), MagicMock(returncode=0), MagicMock(returncode=0), MagicMock(returncode=0), MagicMock(returncode=0)]
        
        print("Running test_commit_changes...")
        ds.commit_changes()
        print("Finished test_commit_changes.")

        mock_run.assert_has_calls([
            call(["git", "-C", self.output_dir, "config", "user.email", "securityonion@local.invalid"], check=True),
            call(["git", "-C", self.output_dir, "config", "user.name", "securityonion"], check=True),
            call(["git", "-C", self.output_dir, "add", "."], check=True),
            call(["git", "-C", self.output_dir, "status"], capture_output=True, text=True),
            call(["git", "-C", self.output_dir, "commit", "-m", "Update detections and overrides"], check=False, capture_output=True)
        ])

    @patch('builtins.print')
    @patch('so-detections-backup.commit_changes')
    @patch('so-detections-backup.save_overrides')
    @patch('so-detections-backup.save_content')
    @patch('so-detections-backup.query_elasticsearch')
    @patch('so-detections-backup.get_auth_credentials')
    @patch('os.makedirs')
    def test_main(self, mock_makedirs, mock_get_auth, mock_query, mock_save_content, mock_save_overrides, mock_commit, mock_print):
        mock_get_auth.return_value = self.auth_credentials
        mock_query.side_effect = [
            {'hits': {'hits': [{"_source": {"so_detection": {"publicId": "1", "content": "content1", "language": "sigma"}}}]}},
            {'hits': {'hits': [{"_source": {"so_detection": {"publicId": "2", "overrides": [{"key": "value"}], "language": "suricata"}}}]}}
        ]
        
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "2024-05-23 20:49:44"
            ds.main()
        
        mock_makedirs.assert_called_once_with(self.output_dir, exist_ok=True)
        mock_get_auth.assert_called_once_with(ds.AUTH_FILE)
        mock_query.assert_has_calls([
            call(ds.QUERY_DETECTIONS, self.auth),
            call(ds.QUERY_OVERRIDES, self.auth)
        ])
        mock_save_content.assert_called_once_with(
            {"_source": {"so_detection": {"publicId": "1", "content": "content1", "language": "sigma"}}}, 
            self.output_dir, 
            "sigma", 
            "yaml"
        )
        mock_save_overrides.assert_called_once_with(
            {"_source": {"so_detection": {"publicId": "2", "overrides": [{"key": "value"}], "language": "suricata"}}}
        )
        mock_commit.assert_called_once()
        mock_print.assert_called()

if __name__ == '__main__':
    unittest.main(verbosity=2)
