"""
Tests for proxy authentication middleware.

Tests the proxy_auth_middleware function that handles automatic authentication
via reverse proxy headers, including admin group restrictions.
"""

from unittest.mock import MagicMock, patch, Mock

import pytest


@pytest.fixture
def mock_session():
    """Mock Flask session."""
    return {}


@pytest.fixture
def mock_request():
    """Mock Flask request."""
    request = Mock()
    request.path = '/api/search'
    request.headers = {}
    return request


class TestProxyAuthMiddleware:
    """Tests for proxy authentication middleware."""

    def test_middleware_skips_for_non_proxy_auth(self, mock_session, mock_request):
        """Test that middleware does nothing when auth mode is not proxy."""
        with patch('shelfmark.main.get_auth_mode', return_value='builtin'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    from shelfmark.main import proxy_auth_middleware
                    
                    result = proxy_auth_middleware()
                    
                    assert result is None
                    assert 'user_id' not in mock_session

    def test_middleware_skips_health_endpoint(self, mock_session, mock_request):
        """Test that middleware skips public health endpoint."""
        mock_request.path = '/api/health'
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    from shelfmark.main import proxy_auth_middleware
                    
                    result = proxy_auth_middleware()
                    
                    assert result is None
                    assert 'user_id' not in mock_session

    def test_middleware_skips_auth_check_endpoint(self, mock_session, mock_request):
        """Test that middleware skips auth check endpoint."""
        mock_request.path = '/api/auth/check'
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    from shelfmark.main import proxy_auth_middleware
                    
                    result = proxy_auth_middleware()
                    
                    assert result is None
                    assert 'user_id' not in mock_session

    def test_middleware_authenticates_user_from_header(self, mock_session, mock_request):
        """Test that middleware authenticates user from proxy header."""
        mock_request.headers = {'X-Auth-User': 'proxyuser'}
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_USER_HEADER': 'X-Auth-User',
                        'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': False
                    }):
                        from shelfmark.main import proxy_auth_middleware
                        
                        result = proxy_auth_middleware()
                        
                        assert result is None
                        assert mock_session['user_id'] == 'proxyuser'
                        assert mock_session['is_admin'] is True
                        assert mock_session['permanent'] is False

    def test_middleware_returns_401_when_header_missing(self, mock_session, mock_request):
        """Test that middleware returns 401 when auth header is missing."""
        mock_request.headers = {}
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_USER_HEADER': 'X-Auth-User'
                    }):
                        from shelfmark.main import proxy_auth_middleware
                        
                        response = proxy_auth_middleware()
                        
                        assert response is not None
                        assert response[1] == 401
                        data = response[0].json
                        assert 'Authentication required' in data['error']

    def test_middleware_checks_admin_group_with_comma_delimiter(self, mock_session, mock_request):
        """Test admin group checking with comma-separated groups."""
        mock_request.headers = {
            'X-Auth-User': 'adminuser',
            'X-Auth-Groups': 'users,admins,developers'
        }
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_USER_HEADER': 'X-Auth-User',
                        'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': True,
                        'PROXY_AUTH_ADMIN_GROUP_HEADER': 'X-Auth-Groups',
                        'PROXY_AUTH_ADMIN_GROUP_NAME': 'admins'
                    }):
                        from shelfmark.main import proxy_auth_middleware
                        
                        result = proxy_auth_middleware()
                        
                        assert result is None
                        assert mock_session['user_id'] == 'adminuser'
                        assert mock_session['is_admin'] is True

    def test_middleware_checks_admin_group_with_pipe_delimiter(self, mock_session, mock_request):
        """Test admin group checking with pipe-separated groups."""
        mock_request.headers = {
            'X-Auth-User': 'adminuser',
            'X-Auth-Groups': 'users|admins|developers'
        }
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_USER_HEADER': 'X-Auth-User',
                        'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': True,
                        'PROXY_AUTH_ADMIN_GROUP_HEADER': 'X-Auth-Groups',
                        'PROXY_AUTH_ADMIN_GROUP_NAME': 'admins'
                    }):
                        from shelfmark.main import proxy_auth_middleware
                        
                        result = proxy_auth_middleware()
                        
                        assert result is None
                        assert mock_session['is_admin'] is True

    def test_middleware_non_admin_user(self, mock_session, mock_request):
        """Test that non-admin users are not granted admin privileges."""
        mock_request.headers = {
            'X-Auth-User': 'normaluser',
            'X-Auth-Groups': 'users,viewers'
        }
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_USER_HEADER': 'X-Auth-User',
                        'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': True,
                        'PROXY_AUTH_ADMIN_GROUP_HEADER': 'X-Auth-Groups',
                        'PROXY_AUTH_ADMIN_GROUP_NAME': 'admins'
                    }):
                        from shelfmark.main import proxy_auth_middleware
                        
                        result = proxy_auth_middleware()
                        
                        assert result is None
                        assert mock_session['user_id'] == 'normaluser'
                        assert mock_session['is_admin'] is False

    def test_middleware_handles_empty_groups_header(self, mock_session, mock_request):
        """Test middleware handles empty groups header gracefully."""
        mock_request.headers = {
            'X-Auth-User': 'user',
            'X-Auth-Groups': ''
        }
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_USER_HEADER': 'X-Auth-User',
                        'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': True,
                        'PROXY_AUTH_ADMIN_GROUP_HEADER': 'X-Auth-Groups',
                        'PROXY_AUTH_ADMIN_GROUP_NAME': 'admins'
                    }):
                        from shelfmark.main import proxy_auth_middleware
                        
                        result = proxy_auth_middleware()
                        
                        assert result is None
                        assert mock_session['is_admin'] is False

    def test_middleware_handles_missing_groups_header(self, mock_session, mock_request):
        """Test middleware handles missing groups header gracefully."""
        mock_request.headers = {'X-Auth-User': 'user'}
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_USER_HEADER': 'X-Auth-User',
                        'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': True,
                        'PROXY_AUTH_ADMIN_GROUP_HEADER': 'X-Auth-Groups',
                        'PROXY_AUTH_ADMIN_GROUP_NAME': 'admins'
                    }):
                        from shelfmark.main import proxy_auth_middleware
                        
                        result = proxy_auth_middleware()
                        
                        assert result is None
                        assert mock_session['is_admin'] is False

    def test_middleware_custom_header_names(self, mock_session, mock_request):
        """Test middleware with custom header names."""
        mock_request.headers = {
            'Custom-User': 'customuser',
            'Custom-Roles': 'role1,role2,superuser'
        }
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_USER_HEADER': 'Custom-User',
                        'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': True,
                        'PROXY_AUTH_ADMIN_GROUP_HEADER': 'Custom-Roles',
                        'PROXY_AUTH_ADMIN_GROUP_NAME': 'superuser'
                    }):
                        from shelfmark.main import proxy_auth_middleware
                        
                        result = proxy_auth_middleware()
                        
                        assert result is None
                        assert mock_session['user_id'] == 'customuser'
                        assert mock_session['is_admin'] is True

    def test_middleware_handles_exception(self, mock_session, mock_request):
        """Test that middleware handles exceptions gracefully."""
        mock_request.headers = {'X-Auth-User': 'user'}
        
        with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
            with patch('shelfmark.main.session', mock_session):
                with patch('shelfmark.main.request', mock_request):
                    with patch('shelfmark.main.load_config_file', side_effect=Exception("Test error")):
                        from shelfmark.main import proxy_auth_middleware
                        
                        response = proxy_auth_middleware()
                        
                        assert response is not None
                        assert response[1] == 500
                        data = response[0].json
                        assert 'Authentication error' in data['error']


class TestLoginRequiredDecorator:
    """Tests for login_required decorator with admin access checks."""

    @pytest.fixture
    def mock_view_function(self):
        """Create a mock view function."""
        def view():
            return {'success': True}, 200
        return view

    def test_login_required_allows_authenticated_user(self, mock_session, mock_view_function):
        """Test that authenticated users can access protected endpoints."""
        mock_session['user_id'] = 'testuser'
        
        with patch('shelfmark.main.session', mock_session):
            with patch('shelfmark.main.get_auth_mode', return_value='builtin'):
                with patch('shelfmark.main.request') as mock_request:
                    mock_request.path = '/api/search'
                    
                    from shelfmark.main import login_required
                    
                    decorated = login_required(mock_view_function)
                    response = decorated()
                    
                    assert response[0]['success'] is True

    def test_login_required_blocks_unauthenticated_user(self, mock_session, mock_view_function):
        """Test that unauthenticated users are blocked."""
        with patch('shelfmark.main.session', mock_session):
            with patch('shelfmark.main.get_auth_mode', return_value='builtin'):
                with patch('shelfmark.main.request') as mock_request:
                    mock_request.path = '/api/search'
                    
                    from shelfmark.main import login_required
                    
                    decorated = login_required(mock_view_function)
                    response = decorated()
                    
                    assert response[1] == 401

    def test_login_required_allows_no_auth_mode(self, mock_session, mock_view_function):
        """Test that all users can access when auth is disabled."""
        with patch('shelfmark.main.session', mock_session):
            with patch('shelfmark.main.get_auth_mode', return_value='none'):
                with patch('shelfmark.main.request') as mock_request:
                    mock_request.path = '/api/search'
                    
                    from shelfmark.main import login_required
                    
                    decorated = login_required(mock_view_function)
                    response = decorated()
                    
                    assert response[0]['success'] is True

    def test_login_required_checks_admin_for_settings(self, mock_session, mock_view_function):
        """Test that admin check is enforced for settings endpoints."""
        mock_session['user_id'] = 'testuser'
        mock_session['is_admin'] = False
        
        with patch('shelfmark.main.session', mock_session):
            with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
                with patch('shelfmark.main.request') as mock_request:
                    mock_request.path = '/api/settings/general'
                    
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': True
                    }):
                        from shelfmark.main import login_required
                        
                        decorated = login_required(mock_view_function)
                        response = decorated()
                        
                        assert response[1] == 403
                        data = response[0].json
                        assert 'Admin access required' in data['error']

    def test_login_required_allows_admin_for_settings(self, mock_session, mock_view_function):
        """Test that admins can access settings endpoints."""
        mock_session['user_id'] = 'adminuser'
        mock_session['is_admin'] = True
        
        with patch('shelfmark.main.session', mock_session):
            with patch('shelfmark.main.get_auth_mode', return_value='proxy'):
                with patch('shelfmark.main.request') as mock_request:
                    mock_request.path = '/api/settings/general'
                    
                    with patch('shelfmark.main.load_config_file', return_value={
                        'PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN': True
                    }):
                        from shelfmark.main import login_required
                        
                        decorated = login_required(mock_view_function)
                        response = decorated()
                        
                        assert response[0]['success'] is True

    def test_login_required_checks_admin_for_onboarding(self, mock_session, mock_view_function):
        """Test that admin check is enforced for onboarding endpoints."""
        mock_session['user_id'] = 'testuser'
        mock_session['is_admin'] = False
        
        with patch('shelfmark.main.session', mock_session):
            with patch('shelfmark.main.get_auth_mode', return_value='cwa'):
                with patch('shelfmark.main.request') as mock_request:
                    mock_request.path = '/api/onboarding'
                    
                    with patch('shelfmark.main.load_config_file', return_value={
                        'CWA_RESTRICT_SETTINGS_TO_ADMIN': True
                    }):
                        from shelfmark.main import login_required
                        
                        decorated = login_required(mock_view_function)
                        response = decorated()
                        
                        assert response[1] == 403

    def test_login_required_allows_non_admin_when_unrestricted(self, mock_session, mock_view_function):
        """Test that non-admins can access settings when not restricted."""
        mock_session['user_id'] = 'testuser'
        mock_session['is_admin'] = False
        
        with patch('shelfmark.main.session', mock_session):
            with patch('shelfmark.main.get_auth_mode', return_value='cwa'):
                with patch('shelfmark.main.request') as mock_request:
                    mock_request.path = '/api/settings/general'
                    
                    with patch('shelfmark.main.load_config_file', return_value={
                        'CWA_RESTRICT_SETTINGS_TO_ADMIN': False
                    }):
                        from shelfmark.main import login_required
                        
                        decorated = login_required(mock_view_function)
                        response = decorated()
                        
                        assert response[0]['success'] is True
