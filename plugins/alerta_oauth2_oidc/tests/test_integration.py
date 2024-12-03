import unittest
import requests
import json

class TestIntegration(unittest.TestCase):

    def setUp(self):
        self.alerta_url = 'http://localhost:8080'
        self.access_token = 'valid_access_token'

    def test_oidc_authentication(self):
        headers = {
            'Content-Type': 'application/json'
        }
        data = {
            'access_token': self.access_token
        }
        response = requests.post(f'{self.alerta_url}/auth/oidc', headers=headers, data=json.dumps(data))

        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json())

    def test_oidc_authentication_invalid_token(self):
        headers = {
            'Content-Type': 'application/json'
        }
        data = {
            'access_token': 'invalid_access_token'
        }
        response = requests.post(f'{self.alerta_url}/auth/oidc', headers=headers, data=json.dumps(data))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['message'], 'Invalid access token')
        