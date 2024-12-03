import logging
import requests
from datetime import datetime, timedelta
from flask import current_app, jsonify, request
from flask_cors import cross_origin
from alerta.auth.utils import create_token, get_customers, not_authorized
from alerta.exceptions import ApiError
from alerta.models.permission import Permission
from alerta.models.user import User
from alerta.plugins import PluginBase
from alerta.utils.audit import auth_audit_trail

LOG = logging.getLogger('alerta.plugins.oauth2_oidc')

class OAuth2OIDCAuthentication(PluginBase):

    def __init__(self):
        super().__init__()

    def get_user_from_token(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(current_app.config['OIDC_USERINFO_URL'], headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            LOG.error(f'Failed to get user info from OIDC provider: {e}')
            raise ApiError('Failed to get user info', 500)

        user_info = response.json()

        # Проверка iss
        if user_info.get('iss') != current_app.config['OIDC_PROVIDER_URL']:
            raise ApiError('Invalid issuer', 401)

        return self._create_user_from_info(user_info)

    def _create_user_from_info(self, user_info):
        return User(
            id=user_info.get(current_app.config['USERINFO_SUB_FIELD']),
            name=user_info.get(current_app.config['USERINFO_NAME_FIELD']),
            login=user_info.get(current_app.config['USERINFO_LOGIN_FIELD']) or user_info.get(current_app.config['USERINFO_EMAIL_FIELD']),
            email=user_info.get(current_app.config['USERINFO_EMAIL_FIELD']),
            roles=[],
            groups=user_info.get(current_app.config['OIDC_GROUPS_CLAIM'], []),
            email_verified=user_info.get(current_app.config['USERINFO_EMAIL_VERIFIED_FIELD'], bool(user_info.get(current_app.config['USERINFO_EMAIL_FIELD'])))
        )

    def authorize(self, username):
        user = User.find_by_username(username=username)
        if not user:
            raise ApiError('User not found', 404)

        if user.status != 'active':
            raise ApiError(f'User {username} is not active', 403)

        return True

    def pre_receive(self, alert, **kwargs):
        return alert

    def post_receive(self, alert, **kwargs):
        return alert

    def status_change(self, alert, status, text, **kwargs):
        return alert, status, text

    def take_action(self, alert, action, text, **kwargs):
        return alert, action, text

    def authenticate(self, **kwargs):
        if 'access_token' not in request.json:
            raise ApiError('Missing access token', 400)

        access_token = request.json['access_token']
        user = self.get_user_from_token(access_token)

        if not user:
            raise ApiError('Invalid access token', 401)

        if user.status != 'active':
            raise ApiError(f'User {user.login} is not active', 403)

        user.update_last_login()

        # Маппинг групп на роли
        for role, groups in current_app.config['GROUP_TO_ROLE_MAPPING'].items():
            if any(group in user.groups for group in groups):
                user.roles.append(role)

        scopes = Permission.lookup(login=user.login, roles=user.roles + user.groups)
        customers = get_customers(login=user.login, groups=user.groups + ([user.domain] if user.domain else []))

        auth_audit_trail.send(current_app._get_current_object(), event='oidc-login', message='user login via OAuth2/OIDC',
                              user=user.login, customers=customers, scopes=scopes, roles=user.roles, groups=user.groups,
                              resource_id=user.id, type='user', request=request)

        token = create_token(user_id=user.id, name=user.name, login=user.login, provider='oidc',
                             customers=customers, scopes=scopes, roles=user.roles, groups=user.groups,
                             email=user.email, email_verified=user.email_verified,
                             expires=datetime.utcnow() + timedelta(seconds=current_app.config['TOKEN_LIFETIME']))
        return jsonify(token=token.tokenize())
    