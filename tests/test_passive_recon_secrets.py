import unittest
from unittest.mock import MagicMock, patch
import json
from adapters.passive_recon import PassiveReconAdapter, AdapterResultStatus

class TestPassiveReconSecrets(unittest.TestCase):
    def setUp(self):
        self.config = {
            "crt_sh": {"timeout": 1},
            "wayback": {"timeout": 1}
        }
        self.adapter = PassiveReconAdapter(self.config)

    @patch('adapters.passive_recon.PassiveReconAdapter._http_get')
    def test_secret_detection_in_wayback(self, mock_get):
        # Mock crt.sh response (empty for this test)
        crt_response = "[]"
        
        # Mock Wayback response with sensitive URLs
        # Header: ["timestamp","original","mime","statuscode","length","digest"]
        wayback_response = json.dumps([
            ["timestamp", "original", "mime", "statuscode", "length", "digest"],
            ["20220101", "http://example.com/index.html", "text/html", "200", "100", "abc"],
            ["20220101", "http://example.com/.env", "text/plain", "200", "50", "def"],
            ["20220101", "http://example.com/config.json", "application/json", "200", "200", "ghi"],
            ["20220101", "http://example.com/api/v1/user?api_key=AIzaSyDummies", "application/json", "200", "150", "jkl"],
            ["20220101", "http://example.com/backup.sql", "application/sql", "200", "5000", "mno"]
        ])

        # Configure mock to return crt_sh first, then wayback
        def side_effect(url, timeout):
            if "crt.sh" in url:
                return crt_response
            if "web.archive.org" in url:
                return wayback_response
            return ""
        
        mock_get.side_effect = side_effect

        # Run execute
        result = self.adapter.execute({"domain": "example.com"})

        # Assertions
        self.assertEqual(result.status, AdapterResultStatus.SUCCESS)
        
        # Check if secrets were detected (This logic hasn't been implemented yet, so we expect this to fail or we check the structure we INTEND to create)
        # We intend to add a 'potential_secrets' key to the data
        
        # For TDD, we assert that the key exists and contains our expected items
        self.assertIn("potential_secrets", result.data)
        secrets = result.data["potential_secrets"]
        self.assertTrue(len(secrets) > 0, "Should have detected secrets")
        
        # Verify specific secrets were caught
        found_env = any(s["url"].endswith(".env") for s in secrets)
        found_key = any("api_key" in s["url"] for s in secrets)
        found_sql = any(s["url"].endswith(".sql") for s in secrets)
        
        self.assertTrue(found_env, "Did not detect .env file")
        self.assertTrue(found_key, "Did not detect api_key parameter")
        self.assertTrue(found_sql, "Did not detect .sql file")

if __name__ == '__main__':
    unittest.main()
