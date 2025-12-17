"""
OIDC Authentication Views for Psono
Handles OIDC/OAuth2 authentication flow with external identity providers
"""
import uuid
import requests
import json
import re
import binascii
import os
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.utils import timezone
from django.http import HttpResponseRedirect
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from rest_framework.parsers import JSONParser

from ..models import User, Token
from ..serializers.oidc_login import OIDCLoginSerializer
from ..utils.various import default_hashing_parameters, encrypt_with_db_secret

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box


# In-memory store for OIDC state and tokens (use Redis/DB in production)
OIDC_STATE_STORE = {}


def get_oidc_config(provider_id):
    """Get OIDC configuration for a specific provider"""
    oidc_configs = getattr(settings, 'OIDC_CONFIGURATIONS', [])
    for config in oidc_configs:
        if config.get('provider_id', 1) == provider_id:
            return config
    # Return first config if provider_id not found
    if oidc_configs:
        return oidc_configs[0]
    return None


class OIDCInitiateLoginView(APIView):
    """
    Initiate OIDC login flow
    POST /oidc/{provider_id}/initiate-login/
    """
    permission_classes = [AllowAny]
    throttle_classes = []
    authentication_classes = []
    parser_classes = [JSONParser]

    def get(self, request, provider_id=1, *args, **kwargs):
        """Handle GET requests - same as POST for convenience"""
        return self.post(request, provider_id, *args, **kwargs)

    def post(self, request, provider_id=1, *args, **kwargs):
        print(f"DEBUG: OIDCInitiateLoginView - request: {request.data}")
        config = get_oidc_config(int(provider_id))
        if not config:
            return Response(
                {'error': 'OIDC provider not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get return URL from request
        return_to_url = request.data.get('return_to_url', '') or request.query_params.get('return_to_url', '')

        # Generate state for CSRF protection
        state = str(uuid.uuid4())
        
        # Store state with request info
        OIDC_STATE_STORE[state] = {
            'provider_id': provider_id,
            'created_at': timezone.now(),
            'return_to_url': return_to_url,
        }

        # Build authorization URL
        auth_params = {
            'client_id': config.get('OIDC_RP_CLIENT_ID'),
            'response_type': 'code',
            'scope': config.get('OIDC_RP_SCOPES', 'openid email profile'),
            'redirect_uri': config.get('OIDC_REDIRECT_URL'),
            'state': state,
            'prompt': 'login',  # Force re-authentication (bypass existing OIDC sessions)
        }

        auth_url = f"{config.get('OIDC_OP_AUTHORIZATION_ENDPOINT')}?{urlencode(auth_params)}"

        return Response({
            'oidc_redirect_url': auth_url,
        })


class OIDCCallbackView(APIView):
    """
    Handle OIDC callback after user authenticates with IdP
    GET /oidc/{provider_id}/callback/
    """
    permission_classes = [AllowAny]
    throttle_classes = []
    authentication_classes = []

    def get(self, request, provider_id=1, *args, **kwargs):
        code = request.query_params.get('code')
        state = request.query_params.get('state')
        error = request.query_params.get('error')

        if error:
            return Response(
                {'error': request.query_params.get('error_description', error)},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not code or not state:
            return Response(
                {'error': 'Missing code or state parameter'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate state
        stored_state = OIDC_STATE_STORE.pop(state, None)
        if not stored_state:
            return Response(
                {'error': 'Invalid state parameter'},
                status=status.HTTP_400_BAD_REQUEST
            )

        config = get_oidc_config(int(provider_id))
        if not config:
            return Response(
                {'error': 'OIDC provider not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Exchange code for tokens
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': config.get('OIDC_REDIRECT_URL'),
            'client_id': config.get('OIDC_RP_CLIENT_ID'),
            'client_secret': config.get('OIDC_RP_CLIENT_SECRET'),
        }

        try:
            token_response = requests.post(
                config.get('OIDC_OP_TOKEN_ENDPOINT'),
                data=token_data,
                verify=config.get('OIDC_VERIFY_SSL', True),
                timeout=10
            )
            token_response.raise_for_status()
            tokens = token_response.json()
        except requests.RequestException as e:
            return Response(
                {'error': f'Failed to exchange code for token: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Get user info
        access_token = tokens.get('access_token')
        
        try:
            userinfo_response = requests.get(
                config.get('OIDC_OP_USER_ENDPOINT'),
                headers={'Authorization': f'Bearer {access_token}'},
                verify=config.get('OIDC_VERIFY_SSL', True),
                timeout=10
            )
            userinfo_response.raise_for_status()
            userinfo = userinfo_response.json()
        except requests.RequestException as e:
            return Response(
                {'error': f'Failed to get user info: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Extract user attributes
        email_attr = config.get('OIDC_EMAIL_ATTRIBUTE', 'email')
        username_attr = config.get('OIDC_USERNAME_ATTRIBUTE', 'email')
        
        email = userinfo.get(email_attr)
        username = userinfo.get(username_attr, email)

        if not email:
            return Response(
                {'error': 'No email in user info'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create OIDC token ID for client to use
        oidc_token_id = str(uuid.uuid4())
        
        # Store the user info for the login endpoint
        OIDC_STATE_STORE[f'token_{oidc_token_id}'] = {
            'email': email,
            'username': username,
            'userinfo': userinfo,
            'provider_id': provider_id,
            'created_at': timezone.now(),
        }

        # Redirect to client with token
        return_to_url = stored_state.get('return_to_url', '')
        if return_to_url:
            # Add token to URL path (client expects /oidc/token/:oidcTokenId route)
            # The return_to_url format is: http://localhost:9000/index.html#!/oidc/token/
            # We need to construct: http://localhost:9000/index.html#!/oidc/token/{token_id}
            print(f"DEBUG: OIDC callback - return_to_url before: {return_to_url}")
            
            # Split URL at the hash to get base URL and hash fragment
            if '#' in return_to_url:
                base_url, hash_fragment = return_to_url.split('#', 1)
                # Remove any existing query parameters or fragments from hash
                hash_fragment = hash_fragment.split('?')[0].split('&')[0]
                
                # Check if hash contains /oidc/token/ pattern
                if '/oidc/token/' in hash_fragment:
                    # Replace /oidc/token/ with /oidc/token/{token_id}
                    new_hash = hash_fragment.replace('/oidc/token/', f'/oidc/token/{oidc_token_id}')
                    redirect_url = f"{base_url}#{new_hash}"
                elif '/oidc/token' in hash_fragment:
                    # Replace /oidc/token with /oidc/token/{token_id}
                    new_hash = hash_fragment.replace('/oidc/token', f'/oidc/token/{oidc_token_id}')
                    redirect_url = f"{base_url}#{new_hash}"
                else:
                    # Fallback: append as hash fragment
                    redirect_url = f"{return_to_url}#oidc/token/{oidc_token_id}"
            else:
                # No hash in URL, append hash with token
                redirect_url = f"{return_to_url}#!/oidc/token/{oidc_token_id}"
            
            print(f"DEBUG: OIDC callback redirect - return_to_url: {return_to_url}, redirect_url: {redirect_url}")
            return HttpResponseRedirect(redirect_url)
        
        return Response({
            'oidc_token_id': oidc_token_id,
            'email': email,
        })


class OIDCLoginView(GenericAPIView):
    """
    Complete OIDC login with token - creates Psono session
    POST /oidc/login/
    
    This receives encrypted login info from the client, decrypts it,
    validates the OIDC token, and creates a Psono session.
    """
    permission_classes = [AllowAny]
    throttle_classes = []
    authentication_classes = []
    serializer_class = OIDCLoginSerializer
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    parser_classes = [JSONParser]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return OIDCLoginSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            # Convert serializer errors to the expected format
            errors = serializer.errors
            if 'non_field_errors' in errors:
                # Already in correct format
                error_list = errors['non_field_errors']
                if not isinstance(error_list, list):
                    error_list = [error_list] if error_list else []
            else:
                # Convert field errors to non_field_errors format
                error_list = []
                for field, field_errors in errors.items():
                    if isinstance(field_errors, list):
                        error_list.extend(field_errors)
                    else:
                        error_list.append(field_errors)
                # If no errors extracted, use a generic error
                if not error_list:
                    error_list = ['INVALID_REQUEST']
            
            return Response(
                {'non_field_errors': error_list}, status=status.HTTP_400_BAD_REQUEST
            )

        oidc_token_id = serializer.validated_data['oidc_token_id']
        user_session_public_key = serializer.validated_data['user_session_public_key']
        session_duration = serializer.validated_data['session_duration']
        device_fingerprint = serializer.validated_data.get('device_fingerprint', '')
        device_description = serializer.validated_data.get('device_description', '')
        device_time = serializer.validated_data.get('device_time')

        # Get stored user info from OIDC callback
        token_key = f'token_{oidc_token_id}'
        token_data = OIDC_STATE_STORE.pop(token_key, None)
        
        if not token_data:
            return Response(
                {'non_field_errors': ['INVALID_OIDC_TOKEN']},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if token is not expired (5 minute validity)
        if timezone.now() - token_data['created_at'] > timedelta(minutes=5):
            return Response(
                {'non_field_errors': ['OIDC_TOKEN_EXPIRED']},
                status=status.HTTP_400_BAD_REQUEST
            )

        email = token_data['email'].lower()
        provider_id = token_data['provider_id']
        
        config = get_oidc_config(int(provider_id))
        create_user = config.get('OIDC_CREATE_USER', True) if config else True

        # Find or create user
        is_new_user = False
        try:
            user = User.objects.get(username=email)
        except User.DoesNotExist:
            if not create_user:
                return Response(
                    {'non_field_errors': ['USER_NOT_FOUND']},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            is_new_user = True
            # Generate user_sauce for new user (needed for key encryption)
            user_sauce = binascii.hexlify(os.urandom(32)).decode()
            hashing_params = default_hashing_parameters()

            # Encrypt email with DB secret (same as regular user creation)
            encrypted_email = encrypt_with_db_secret(email)

            user = User.objects.create(
                username=email,
                email=encrypted_email,
                email_bcrypt='OIDC_USER',  # Marker for OIDC users
                authkey='',
                public_key='',  # Will be set during setup
                private_key='',  # Will be set during setup
                private_key_nonce=None,  # Use None instead of '' to avoid UNIQUE constraint violations
                secret_key='',  # Will be set during setup
                secret_key_nonce=None,  # Use None instead of '' to avoid UNIQUE constraint violations
                user_sauce=user_sauce,
                hashing_algorithm='scrypt',
                hashing_parameters=hashing_params,
                is_email_active=True,
                is_active=True,
                authentication='OIDC',
            )

        if not user.is_active:
            return Response(
                {'non_field_errors': ['USER_DISABLED']},
                status=status.HTTP_403_FORBIDDEN
            )

        # Check if user needs to set up their vault (no private key)
        needs_setup = not user.private_key or user.private_key == ''
        
        if needs_setup:
            # Store user info for setup endpoint
            setup_token_id = str(uuid.uuid4())
            OIDC_STATE_STORE[f'setup_{setup_token_id}'] = {
                'user_id': str(user.id),
                'email': email,
                'created_at': timezone.now(),
            }
            
            # Return needs_setup response
            response_data = {
                'needs_setup': True,
                'setup_token_id': setup_token_id,
                'user_sauce': user.user_sauce,
                'hashing_algorithm': user.hashing_algorithm,
                'hashing_parameters': user.hashing_parameters,
                'username': user.username,
            }
            
            # Encrypt the response
            server_crypto_box = Box(
                PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
                PublicKey(user_session_public_key, encoder=nacl.encoding.HexEncoder)
            )
            login_info_nonce = nacl.utils.random(Box.NONCE_SIZE)
            login_info_nonce_hex = nacl.encoding.HexEncoder.encode(login_info_nonce)
            encrypted = server_crypto_box.encrypt(json.dumps(response_data).encode(), login_info_nonce)
            encrypted_login_info = encrypted[len(login_info_nonce):]
            encrypted_login_info_hex = nacl.encoding.HexEncoder.encode(encrypted_login_info)
            
            return Response({
                'login_info': encrypted_login_info_hex,
                'login_info_nonce': login_info_nonce_hex
            }, status=status.HTTP_200_OK)

        # Create session token
        token = Token.objects.create(
            user=user,
            device_fingerprint=device_fingerprint,
            device_description=device_description,
            client_date=device_time,
            valid_till=timezone.now() + timedelta(seconds=session_duration),
            read=True,
            write=True,
        )

        # Generate session key exchange (same as regular login)
        box = PrivateKey.generate()
        server_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        server_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)

        # Encrypt session secret with session crypto box
        session_crypto_box = Box(
            PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
            PublicKey(user_session_public_key, encoder=nacl.encoding.HexEncoder)
        )
        session_secret_key_nonce = nacl.utils.random(Box.NONCE_SIZE)
        session_secret_key_nonce_hex = nacl.encoding.HexEncoder.encode(session_secret_key_nonce)
        encrypted = session_crypto_box.encrypt(token.secret_key.encode(), session_secret_key_nonce)
        session_secret_key = encrypted[len(session_secret_key_nonce):]
        session_secret_key_hex = nacl.encoding.HexEncoder.encode(session_secret_key)

        # Encrypt user validator (if user has public key)
        user_validator_nonce_hex = b''
        user_validator_hex = b''
        
        if user.public_key:
            try:
                user_crypto_box = Box(
                    PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                    PublicKey(user.public_key, encoder=nacl.encoding.HexEncoder)
                )
                user_validator_nonce = nacl.utils.random(Box.NONCE_SIZE)
                user_validator_nonce_hex = nacl.encoding.HexEncoder.encode(user_validator_nonce)
                user_validator_encrypted = user_crypto_box.encrypt(token.user_validator.encode(), user_validator_nonce)
                user_validator = user_validator_encrypted[len(user_validator_nonce):]
                user_validator_hex = nacl.encoding.HexEncoder.encode(user_validator)
            except Exception as e:
                print(f"DEBUG: Failed to encrypt user validator: {e}")

        # Build response data (same structure as regular login)
        response_data = {
            "token": token.clear_text_key,
            "session_key": token.session_key,
            "session_valid_till": token.valid_till.isoformat(),
            "required_multifactors": [],  # OIDC users skip MFA (handled by IdP)
            "session_public_key": server_session_public_key_hex.decode('utf-8'),
            "session_secret_key": session_secret_key_hex.decode('utf-8'),
            "session_secret_key_nonce": session_secret_key_nonce_hex.decode('utf-8'),
            "user_validator": user_validator_hex.decode('utf-8') if user_validator_hex else '',
            "user_validator_nonce": user_validator_nonce_hex.decode('utf-8') if user_validator_nonce_hex else '',
            "user": {
                "username": user.username,
                "language": user.language if hasattr(user, 'language') else '',
                "public_key": user.public_key,
                "private_key": user.private_key,
                "private_key_nonce": user.private_key_nonce,
                "user_sauce": user.user_sauce if hasattr(user, 'user_sauce') else '',
                "authentication": 'OIDC',
                'hashing_algorithm': user.hashing_algorithm if hasattr(user, 'hashing_algorithm') else '',
                'hashing_parameters': user.hashing_parameters if hasattr(user, 'hashing_parameters') else '',
            }
        }

        # Encrypt the response data (same as regular login)
        server_crypto_box = Box(
            PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
            PublicKey(user_session_public_key, encoder=nacl.encoding.HexEncoder)
        )
        login_info_nonce = nacl.utils.random(Box.NONCE_SIZE)
        login_info_nonce_hex = nacl.encoding.HexEncoder.encode(login_info_nonce)
        encrypted = server_crypto_box.encrypt(json.dumps(response_data).encode(), login_info_nonce)
        encrypted_login_info = encrypted[len(login_info_nonce):]
        encrypted_login_info_hex = nacl.encoding.HexEncoder.encode(encrypted_login_info)

        return Response({
            'login_info': encrypted_login_info_hex,
            'login_info_nonce': login_info_nonce_hex
        }, status=status.HTTP_200_OK)


class OIDCSetupKeysView(APIView):
    """
    Set up encryption keys for OIDC users
    POST /oidc/setup-keys/
    
    Called after a new OIDC user logs in for the first time.
    Receives the user's encrypted keys, stores them, and returns a full login response.
    """
    permission_classes = [AllowAny]
    throttle_classes = []
    authentication_classes = []
    parser_classes = [JSONParser]

    def post(self, request, *args, **kwargs):
        setup_token_id = request.data.get('setup_token_id')
        public_key = request.data.get('public_key')
        private_key = request.data.get('private_key')
        private_key_nonce = request.data.get('private_key_nonce')
        secret_key = request.data.get('secret_key')
        secret_key_nonce = request.data.get('secret_key_nonce')
        user_session_public_key = request.data.get('user_session_public_key')
        session_duration = request.data.get('session_duration', 24 * 60 * 60)
        device_fingerprint = request.data.get('device_fingerprint', '')
        device_description = request.data.get('device_description', '')
        
        if not all([setup_token_id, public_key, private_key, private_key_nonce, secret_key, secret_key_nonce, user_session_public_key]):
            return Response(
                {'error': 'Missing required fields'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get stored setup info
        setup_key = f'setup_{setup_token_id}'
        setup_data = OIDC_STATE_STORE.pop(setup_key, None)
        
        if not setup_data:
            return Response(
                {'error': 'Invalid or expired setup token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if token is not expired (10 minute validity)
        if timezone.now() - setup_data['created_at'] > timedelta(minutes=10):
            return Response(
                {'error': 'Setup token expired'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get user and update keys
        try:
            user = User.objects.get(id=setup_data['user_id'])
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Update user with encrypted keys
        user.public_key = public_key
        user.private_key = private_key
        user.private_key_nonce = private_key_nonce
        user.secret_key = secret_key
        user.secret_key_nonce = secret_key_nonce
        user.save()
        
        # Now create a full login session (same as OIDCLoginView)
        # Create session token
        token = Token.objects.create(
            user=user,
            device_fingerprint=device_fingerprint,
            device_description=device_description,
            client_date=timezone.now(),
            valid_till=timezone.now() + timedelta(seconds=session_duration),
            read=True,
            write=True,
        )

        # Generate session key exchange
        box = PrivateKey.generate()
        server_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        server_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)

        # Encrypt session secret with session crypto box
        session_crypto_box = Box(
            PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
            PublicKey(user_session_public_key, encoder=nacl.encoding.HexEncoder)
        )
        session_secret_key_nonce = nacl.utils.random(Box.NONCE_SIZE)
        session_secret_key_nonce_hex = nacl.encoding.HexEncoder.encode(session_secret_key_nonce)
        encrypted = session_crypto_box.encrypt(token.secret_key.encode(), session_secret_key_nonce)
        session_secret_key = encrypted[len(session_secret_key_nonce):]
        session_secret_key_hex = nacl.encoding.HexEncoder.encode(session_secret_key)

        # Encrypt user validator with user's public key
        user_validator_nonce_hex = b''
        user_validator_hex = b''
        
        try:
            user_crypto_box = Box(
                PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                PublicKey(public_key, encoder=nacl.encoding.HexEncoder)
            )
            user_validator_nonce = nacl.utils.random(Box.NONCE_SIZE)
            user_validator_nonce_hex = nacl.encoding.HexEncoder.encode(user_validator_nonce)
            user_validator_encrypted = user_crypto_box.encrypt(token.user_validator.encode(), user_validator_nonce)
            user_validator = user_validator_encrypted[len(user_validator_nonce):]
            user_validator_hex = nacl.encoding.HexEncoder.encode(user_validator)
        except Exception as e:
            print(f"DEBUG: Failed to encrypt user validator: {e}")

        # Build response data (same structure as regular login)
        response_data = {
            "token": token.clear_text_key,
            "session_key": token.session_key,
            "session_valid_till": token.valid_till.isoformat(),
            "required_multifactors": [],  # OIDC users skip MFA
            "session_public_key": server_session_public_key_hex.decode('utf-8'),
            "session_secret_key": session_secret_key_hex.decode('utf-8'),
            "session_secret_key_nonce": session_secret_key_nonce_hex.decode('utf-8'),
            "user_validator": user_validator_hex.decode('utf-8') if user_validator_hex else '',
            "user_validator_nonce": user_validator_nonce_hex.decode('utf-8') if user_validator_nonce_hex else '',
            "user": {
                "username": user.username,
                "language": user.language if hasattr(user, 'language') else '',
                "public_key": public_key,
                "private_key": private_key,
                "private_key_nonce": private_key_nonce,
                "user_sauce": user.user_sauce if hasattr(user, 'user_sauce') else '',
                "authentication": 'OIDC',
                'hashing_algorithm': user.hashing_algorithm if hasattr(user, 'hashing_algorithm') else '',
                'hashing_parameters': user.hashing_parameters if hasattr(user, 'hashing_parameters') else '',
            }
        }

        # Encrypt the response data
        server_crypto_box = Box(
            PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
            PublicKey(user_session_public_key, encoder=nacl.encoding.HexEncoder)
        )
        login_info_nonce = nacl.utils.random(Box.NONCE_SIZE)
        login_info_nonce_hex = nacl.encoding.HexEncoder.encode(login_info_nonce)
        encrypted = server_crypto_box.encrypt(json.dumps(response_data).encode(), login_info_nonce)
        encrypted_login_info = encrypted[len(login_info_nonce):]
        encrypted_login_info_hex = nacl.encoding.HexEncoder.encode(encrypted_login_info)

        return Response({
            'login_info': encrypted_login_info_hex,
            'login_info_nonce': login_info_nonce_hex
        }, status=status.HTTP_200_OK)
