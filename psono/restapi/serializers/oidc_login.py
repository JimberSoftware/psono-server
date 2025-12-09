"""
OIDC Login Serializer
Handles decryption and validation of OIDC login requests
"""
from django.conf import settings

import dateutil.parser
import nacl.encoding
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

import json

from rest_framework import serializers, exceptions


class OIDCLoginSerializer(serializers.Serializer):
    """Serializer for OIDC login - similar to LoginSerializer but for OIDC tokens"""
    
    public_key = serializers.CharField(required=True, min_length=64, max_length=64)
    login_info = serializers.CharField(required=True)
    login_info_nonce = serializers.CharField(required=True)
    session_duration = serializers.IntegerField(required=False)

    def validate(self, attrs: dict) -> dict:
        login_info = attrs.get('login_info')
        login_info_nonce = attrs.get('login_info_nonce')
        public_key = attrs.get('public_key')
        session_duration = attrs.get('session_duration', getattr(settings, 'DEFAULT_TOKEN_TIME_VALID', 86400))

        # Decrypt the login info using server's private key
        crypto_box = Box(
            PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
            PublicKey(public_key, encoder=nacl.encoding.HexEncoder)
        )

        try:
            request_data = json.loads(crypto_box.decrypt(
                nacl.encoding.HexEncoder.decode(login_info),
                nacl.encoding.HexEncoder.decode(login_info_nonce)
            ).decode())
        except Exception:
            msg = 'LOGIN_INFO_CANNOT_BE_DECRYPTED'
            raise exceptions.ValidationError(msg)

        oidc_token_id = request_data.get('oidc_token_id')
        if not oidc_token_id:
            msg = 'OIDC_TOKEN_REQUIRED'
            raise exceptions.ValidationError(msg)

        # Limit session duration
        session_duration = min(session_duration, getattr(settings, 'MAX_WEB_TOKEN_TIME_VALID', 86400 * 30))
        session_duration = max(session_duration, getattr(settings, 'MIN_WEB_TOKEN_TIME_VALID', 60))

        attrs['oidc_token_id'] = oidc_token_id
        attrs['user_session_public_key'] = public_key
        attrs['session_duration'] = session_duration

        attrs['device_fingerprint'] = request_data.get('device_fingerprint', '')
        attrs['device_description'] = request_data.get('device_description', '')

        device_time = request_data.get('device_time', None)
        if device_time is None:
            attrs['device_time'] = None
        else:
            try:
                attrs['device_time'] = dateutil.parser.parse(device_time)
            except:
                attrs['device_time'] = None

        return attrs

