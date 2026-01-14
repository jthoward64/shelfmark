"""
Tests for authentication API endpoints.

Tests the /api/auth/login, /api/auth/logout, and /api/auth/check endpoints
with different authentication modes (none, builtin, cwa, proxy).
"""

import json
from unittest.mock import MagicMock, patch, Mock

import pytest
from flask import Flask


@pytest.fixture
def mock_flask_app():
    """Create a mock Flask app for testing."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    return app


@pytest.fixture
def mock_session():
    """Mock Flask session."""
    return {}


class TestAuthCheckEndpoint:
    """Tests for /api/auth/check endpoint."""

    def test_auth_check_with_no_auth(self, mock_session):
        """Test auth check when no authentication is required."""
        with patch('shelfmark.main.get_auth_mode', return_value='none'):
            with patch('shelfmark.main.session', mock_session):
                from shelfmark.main import api_auth_check
                
                response = api_auth_check()
                data = response[0].json
                
                assert data['authenticated'] is True
                assert data['auth_required'] is False
                assert data['is_admin'] is True
                assert data['auth_mode'] == 'none'

    def test_auth_check_with_builtin_authenticated(self, mock_session):
        """Test auth check with builtin auth when user is authenticated."""
        mock_session['user_id'] = 'admin'
        
        with patch('shelfmark.main.get_auth_mode', return_value='builtin'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={}):
                    from shelfmark.main import api_auth_check
                    
                    response = api_auth_check()
                    data = response[0].json
                    
                    assert data['authenticated'] is True
                    assert data['auth_required'] is True
                    assert data['is_admin'] is True  # Builtin users are always admin
                    assert data['auth_mode'] == 'builtin'
                    assert data['username'] == 'admin'

    def test_auth_check_with_builtin_not_authenticated(self, mock_session):
        """Test auth check with builtin auth when user is not authenticated."""
        with patch('shelfmark.main.get_auth_mode', return_value='builtin'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={}):
                    from shelfmark.main import api_auth_check
                    
                    response = api_auth_check()
                    data = response[0].json
                    
                    assert data['authenticated'] is False
                    assert data['auth_required'] is True
                    assert data['is_admin'] is False
                    assert data['auth_mode'] == 'builtin'

    def test_auth_check_with_cwa_admin(self, mock_session):
        """Test auth check with CWA auth when user is admin."""
        mock_session['user_id'] = 'admin'
        mock_session['is_admin'] = True
        
        with patch('shelfmark.main.get_auth_mode', return_value='cwa'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={'CWA_RESTRICT_SETTINGS_TO_ADMIN': True}):
                    from shelfmark.main import api_auth_check
                    
                    response = api_auth_check()
                    data = response[0].json
                    
                    assert data['authenticated'] is True
                    assert data['is_admin'] is True

    def test_auth_check_with_cwa_non_admin_restricted(self, mock_session):
        """Test auth check with CWA auth when non-admin and settings restricted."""
        mock_session['user_id'] = 'user'
        mock_session['is_admin'] = False
        
        with patch('shelfmark.main.get_auth_mode', return_value='cwa'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={'CWA_RESTRICT_SETTINGS_TO_ADMIN': True}):
                    from shelfmark.main import api_auth_check
                    
                    response = api_auth_check()
                    data = response[0].json
                    
                    assert data['authenticated'] is True
                    assert data['is_admin'] is False

    def test_auth_check_with_cwa_non_admin_unrestricted(self, mock_session):
        """Test auth check with CWA auth when non-admin and settings not restricted."""
        mock_session['user_id'] = 'user'
        mock_session['is_admin'] = False
        
        with patch('shelfmark.main.get_auth_mode', return_value='cwa'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={'CWA_RESTRICT_SETTINGS_TO_ADMIN': False}):
                    from shelfmark.main import api_auth_check
                    
                    response = api_auth_check()
                    data = response[0].json
                    
                    assert data['authenticated'] is True
                    assert data['is_admin'] is True  # All CWA users are admin when not restricted

    def test_auth_check_with_proxy_admin(self, mock_session):
        """Test auth check with proxy auth when user is admin."""
        mock_session['user_id'] = 'admin'
        mock_session['is_admin'] = True
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={
                    'PROXY_AUTH_USER_HEADER': 'X-Auth-User',
                    'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': True,
                    'PROXY_AUTH_LOGOUT_URL': 'https://auth.example.com/logout'
                }):
                    from shelfmark.main import api_auth_check
                    
                    response = api_auth_check()
                    data = response[0].json
                    
                    assert data['authenticated'] is True
                    assert data['is_admin'] is True
                    assert data['logout_url'] == 'https://auth.example.com/logout'

    def test_auth_check_with_proxy_non_admin_unrestricted(self, mock_session):
        """Test auth check with proxy auth when non-admin and settings not restricted."""
        mock_session['user_id'] = 'user'
        mock_session['is_admin'] = False
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={
                    'PROXY_AUTH_USER_HEADER': 'X-Auth-User',
                    'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': False
                }):
                    from shelfmark.main import api_auth_check
                    
                    response = api_auth_check()
                    data = response[0].json
                    
                    assert data['authenticated'] is True
                    # When settings not restricted, is_admin should be True
                    assert data['is_admin'] is True


class TestLoginEndpoint:
    """Tests for /api/auth/login endpoint."""

    def test_login_with_no_auth(self, mock_session):
        """Test login when no authentication is required."""
        with patch('shelfmark.main.get_auth_mode', return_value='none'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request') as mock_request:
                    with patch('shelfmark.main.clear_failed_logins'):
                        mock_request.json = {'username': 'anyuser', 'password': 'anypass', 'remember_me': False}
                        mock_request.args = {}
                        
                        from shelfmark.main import api_login
                        
                        response = api_login()
                        data = response[0].json
                        
                        assert data['success'] is True
                        assert mock_session['user_id'] == 'anyuser'

    def test_login_with_proxy_auth(self, mock_session):
        """Test login when proxy authentication is enabled."""
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request') as mock_request:
                    with patch('shelfmark.main.clear_failed_logins'):
                        mock_request.json = {'username': 'proxyuser', 'password': 'anypass', 'remember_me': False}
                        mock_request.args = {}
                        
                        from shelfmark.main import api_login
                        
                        response = api_login()
                        data = response[0].json
                        
                        assert data['success'] is True
                        assert mock_session['user_id'] == 'proxyuser'

    def test_login_with_builtin_success(self, mock_session):
        """Test successful login with builtin authentication."""
        with patch('shelfmark.main.get_auth_mode', return_value='builtin'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request') as mock_request:
                    with patch('shelfmark.main.is_account_locked', return_value=False):
                        with patch('shelfmark.main.load_config_file', return_value={
                            'BUILTIN_USERNAME': 'admin',
                            'BUILTIN_PASSWORD_HASH': 'pbkdf2:sha256:600000$abcdef$1234567890'
                        }):
                            with patch('shelfmark.main.check_password_hash', return_value=True):
                                with patch('shelfmark.main.clear_failed_logins'):
                                    with patch('shelfmark.main.get_client_ip', return_value='127.0.0.1'):
                                        mock_request.json = {'username': 'admin', 'password': 'correct', 'remember_me': True}
                                        mock_request.args = {}
                                        
                                        from shelfmark.main import api_login
                                        
                                        response = api_login()
                                        data = response[0].json
                                        
                                        assert data['success'] is True
                                        assert mock_session['user_id'] == 'admin'
                                        assert mock_session['permanent'] is True

    def test_login_with_builtin_wrong_password(self, mock_session):
        """Test failed login with wrong password."""
        with patch('shelfmark.main.get_auth_mode', return_value='builtin'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request') as mock_request:
                    with patch('shelfmark.main.is_account_locked', return_value=False):
                        with patch('shelfmark.main.load_config_file', return_value={
                            'BUILTIN_USERNAME': 'admin',
                            'BUILTIN_PASSWORD_HASH': 'pbkdf2:sha256:600000$abcdef$1234567890'
                        }):
                            with patch('shelfmark.main.check_password_hash', return_value=False):
                                with patch('shelfmark.main.record_failed_login', return_value=False):
                                    with patch('shelfmark.main.get_client_ip', return_value='127.0.0.1'):
                                        with patch('shelfmark.main.failed_login_attempts', {'admin': {'count': 1}}):
                                            mock_request.json = {'username': 'admin', 'password': 'wrong', 'remember_me': False}
                                            mock_request.args = {}
                                            
                                            from shelfmark.main import api_login
                                            
                                            response = api_login()
                                            data = response[0].json
                                            
                                            assert response[1] == 401
                                            assert data['error'] is not None

    def test_login_with_account_locked(self, mock_session):
        """Test login when account is locked."""
        with patch('shelfmark.main.get_auth_mode', return_value='builtin'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request') as mock_request:
                    with patch('shelfmark.main.is_account_locked', return_value=True):
                        with patch('shelfmark.main.get_client_ip', return_value='127.0.0.1'):
                            mock_request.json = {'username': 'admin', 'password': 'anypass', 'remember_me': False}
                            mock_request.args = {}
                            
                            from shelfmark.main import api_login
                            
                            response = api_login()
                            data = response[0].json
                            
                            assert response[1] == 403
                            assert 'locked' in data['error'].lower()

    def test_login_with_cwa_success(self, mock_session):
        """Test successful login with Calibre-Web authentication."""
        with patch('shelfmark.main.get_auth_mode', return_value='cwa'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request') as mock_request:
                    with patch('shelfmark.main.is_account_locked', return_value=False):
                        with patch('shelfmark.main._verify_cwa_credentials', return_value=(True, True)):
                            with patch('shelfmark.main.clear_failed_logins'):
                                with patch('shelfmark.main.get_client_ip', return_value='127.0.0.1'):
                                    mock_request.json = {'username': 'cwauser', 'password': 'correct', 'remember_me': False}
                                    mock_request.args = {}
                                    
                                    from shelfmark.main import api_login
                                    
                                    response = api_login()
                                    data = response[0].json
                                    
                                    assert data['success'] is True
                                    assert mock_session['user_id'] == 'cwauser'
                                    assert mock_session['is_admin'] is True


class TestLogoutEndpoint:
    """Tests for /api/auth/logout endpoint."""

    def test_logout_basic(self, mock_session):
        """Test basic logout functionality."""
        mock_session['user_id'] = 'admin'
        
        with patch('shelfmark.main.get_auth_mode', return_value='builtin'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={}):
                    with patch('shelfmark.main.get_client_ip', return_value='127.0.0.1'):
                        from shelfmark.main import api_logout
                        
                        response = api_logout()
                        data = response[0].json
                        
                        assert data['success'] is True
                        assert 'logout_url' not in data
                        assert len(mock_session) == 0  # Session cleared

    def test_logout_with_proxy_and_logout_url(self, mock_session):
        """Test logout with proxy auth returns logout URL."""
        mock_session['user_id'] = 'proxyuser'
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={
                    'PROXY_AUTH_LOGOUT_URL': 'https://auth.example.com/logout'
                }):
                    with patch('shelfmark.main.get_client_ip', return_value='127.0.0.1'):
                        from shelfmark.main import api_logout
                        
                        response = api_logout()
                        data = response[0].json
                        
                        assert data['success'] is True
                        assert data['logout_url'] == 'https://auth.example.com/logout'

    def test_logout_with_proxy_no_logout_url(self, mock_session):
        """Test logout with proxy auth when no logout URL is configured."""
        mock_session['user_id'] = 'proxyuser'
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.load_config_file', return_value={
                    'PROXY_AUTH_LOGOUT_URL': ''
                }):
                    with patch('shelfmark.main.get_client_ip', return_value='127.0.0.1'):
                        from shelfmark.main import api_logout
                        
                        response = api_logout()
                        data = response[0].json
                        
                        assert data['success'] is True
                        assert 'logout_url' not in data


class TestGetAuthMode:
    """Tests for the get_auth_mode helper function."""

    def test_get_auth_mode_none(self):
        """Test get_auth_mode returns 'none' when no auth is configured."""
        with patch('shelfmark.main.load_config_file', return_value={'AUTH_METHOD': 'none'}):
            from shelfmark.main import get_auth_mode
            
            assert get_auth_mode() == 'none'

    def test_get_auth_mode_builtin(self):
        """Test get_auth_mode returns 'builtin' when credentials are configured."""
        with patch('shelfmark.main.load_config_file', return_value={
            'AUTH_METHOD': 'builtin',
            'BUILTIN_USERNAME': 'admin',
            'BUILTIN_PASSWORD_HASH': 'hashed_password'
        }):
            from shelfmark.main import get_auth_mode
            
            assert get_auth_mode() == 'builtin'

    def test_get_auth_mode_proxy(self):
        """Test get_auth_mode returns 'proxy' when proxy auth is configured."""
        with patch('shelfmark.main.load_config_file', return_value={
            'AUTH_METHOD': 'proxy',
            'PROXY_AUTH_USER_HEADER': 'X-Auth-User'
        }):
            from shelfmark.main import get_auth_mode
            
            assert get_auth_mode() == 'proxy'

    def test_get_auth_mode_cwa(self):
        """Test get_auth_mode returns 'cwa' when CWA DB is available."""
        with patch('shelfmark.main.load_config_file', return_value={'AUTH_METHOD': 'cwa'}):
            with patch('shelfmark.main.CWA_DB_PATH', Mock(exists=lambda: True)):
                from shelfmark.main import get_auth_mode
                
                assert get_auth_mode() == 'cwa'

    def test_get_auth_mode_default_on_error(self):
        """Test get_auth_mode returns 'none' on error."""
        with patch('shelfmark.main.load_config_file', side_effect=Exception("Test error")):
            from shelfmark.main import get_auth_mode
            
            assert get_auth_mode() == 'none'


class TestRateLimiting:
    """Tests for login rate limiting and account lockout."""

    def test_record_failed_login_increments_count(self):
        """Test that failed login attempts are tracked."""
        from shelfmark.main import record_failed_login, failed_login_attempts
        
        # Clear any existing state
        failed_login_attempts.clear()
        
        is_locked = record_failed_login('testuser', '127.0.0.1')
        
        assert is_locked is False
        assert 'testuser' in failed_login_attempts
        assert failed_login_attempts['testuser']['count'] == 1

    def test_account_locked_after_max_attempts(self):
        """Test that account is locked after maximum failed attempts."""
        from shelfmark.main import record_failed_login, failed_login_attempts, MAX_LOGIN_ATTEMPTS
        
        failed_login_attempts.clear()
        
        # Record MAX_LOGIN_ATTEMPTS failed attempts
        for _ in range(MAX_LOGIN_ATTEMPTS):
            is_locked = record_failed_login('testuser', '127.0.0.1')
        
        assert is_locked is True
        assert 'lockout_until' in failed_login_attempts['testuser']

    def test_is_account_locked(self):
        """Test checking if account is locked."""
        from datetime import datetime, timedelta
        from shelfmark.main import is_account_locked, failed_login_attempts
        
        failed_login_attempts.clear()
        
        # Lock account for 1 hour in the future
        failed_login_attempts['testuser'] = {
            'count': 10,
            'lockout_until': datetime.now() + timedelta(hours=1)
        }
        
        assert is_account_locked('testuser') is True

    def test_clear_failed_logins(self):
        """Test clearing failed login attempts."""
        from shelfmark.main import clear_failed_logins, failed_login_attempts
        
        failed_login_attempts['testuser'] = {'count': 5}
        
        clear_failed_logins('testuser')
        
        assert 'testuser' not in failed_login_attempts
