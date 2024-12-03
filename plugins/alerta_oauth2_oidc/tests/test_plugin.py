import unittest
from unittest.mock import patch, MagicMock
from alerta_oauth2_oidc.plugin import OAuth2OIDCAuthentication

class TestOAuth2OIDCAuthentication(unittest.TestCase):

    @patch('requests.get')
    def test_get_user_from_token(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'sub': '7ecaf315-737f-4c53-a053-8a97d827939f',
            'name': 'Test User',
            'preferred_username': 'testuser',
            'email': 'testuser@cyber.bar',
            'roles': [],
            'groups': ['ADMIN:SECURITY'],
            'email_verified': True
        }
        mock_get.return_value = mock_response

        plugin = OAuth2OIDCAuthentication()
        user = plugin.get_user_from_token('test_token')

        self.assertEqual(user.id, '7ecaf315-737f-4c53-a053-8a97d827939f')
        self.assertEqual(user.name, 'Test User')
        self.assertEqual(user.login, 'testuser')
        self.assertEqual(user.email, 'testuser@cyber.bar')
        self.assertEqual(user.roles, [])
        self.assertEqual(user.groups, ['ADMIN:SECURITY'])
        self.assertTrue(user.email_verified)

    @patch('requests.get')
    def test_get_user_from_token_failure(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        plugin = OAuth2OIDCAuthentication()
        with self.assertRaises(Exception):
            plugin.get_user_from_token('invalid_token')

    @patch('alerta.models.user.User.find_by_username')
    def test_authorize(self, mock_find_by_username):
        mock_user = MagicMock()
        mock_user.status = 'active'
        mock_user.roles = ['admin']
        mock_user.domain = 'cyber.bar'
        mock_find_by_username.return_value = mock_user

        plugin = OAuth2OIDCAuthentication()
        result = plugin.authorize('testuser')

        self.assertTrue(result)

    @patch('alerta.models.user.User.find_by_username')
    def test_authorize_user_not_found(self, mock_find_by_username):
        mock_find_by_username.return_value = None

        plugin = OAuth2OIDCAuthentication()
        with self.assertRaises(Exception):
            plugin.authorize('nonexistentuser')

    @patch('alerta.models.user.User.find_by_username')
    def test_authorize_user_not_active(self, mock_find_by_username):
        mock_user = MagicMock()
        mock_user.status = 'inactive'
        mock_find_by_username.return_value = mock_user

        plugin = OAuth2OIDCAuthentication()
        with self.assertRaises(Exception):
            plugin.authorize('inactiveuser')

    @patch('alerta.models.user.User.find_by_username')
    def test_authorize_user_not_authorized(self, mock_find_by_username):
        mock_user = MagicMock()
        mock_user.status = 'active'
        mock_user.roles = ['user']
        mock_user.domain = 'cyber.bar'
        mock_find_by_username.return_value = mock_user

        plugin = OAuth2OIDCAuthentication()
        with self.assertRaises(Exception):
            plugin.authorize('unauthorizeduser')
