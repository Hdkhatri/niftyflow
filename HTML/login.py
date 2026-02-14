import sys
import os
import json
import logging
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime, timedelta
import sqlite3
import re

from htmlconfig import PATH, DB_PATH

login_bp = Blueprint('login_bp', __name__)

# Add parent directory to path for imports
if PATH and PATH not in sys.path:
    sys.path.insert(0, PATH)

# Import commonFunction module
try:
    from commonFunction import check_login_success, DB_FILE, get_profile
    from config import LOG_FILE
except ImportError:
    print("❌ Error: commonFunction.py not found in parent directory")
    # Fallback logging
    LOG_FILE = 'logs/login.log'

# Configure logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Store CAPTCHA codes temporarily (in production, use Redis or database)
captcha_store = {}


@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle login page display (GET) and login validation (POST)
    """
    if request.method == 'GET':
        # Check if user is already logged in with valid session
        if 'user_id' in session and 'username' in session:
            logger.info(f"User {session.get('username')} already logged in, redirecting to dashboard")
            return redirect(url_for('login_bp.dashboard'))
        
        # Clear any residual session data
        session.clear()
        logger.info("GET request to login page")
        return render_template('login.html')
    
    elif request.method == 'POST':
        """
        Handle POST login request with JSON response
        """
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            captcha_input = request.form.get('captcha', '').strip()

            # Initialize response
            response_data = {
                'success': False,
                'message': '',
                'redirect': '/dashboard'
            }

            # ===== Validation Checks =====
            
            # 1. Validate username
            if not username:
                logger.warning("Login attempt with empty username")
                response_data['message'] = 'Username is required'
                return jsonify(response_data), 400

            if len(username) < 3:
                logger.warning(f"Login attempt with username too short: {username}")
                response_data['message'] = 'Username must be at least 3 characters'
                return jsonify(response_data), 400

            if not is_valid_username(username):
                logger.warning(f"Login attempt with invalid username format: {username}")
                response_data['message'] = 'Username contains invalid characters'
                return jsonify(response_data), 400

            # 2. Validate password
            if not password:
                logger.warning(f"Login attempt with empty password for user: {username}")
                response_data['message'] = 'Password is required'
                return jsonify(response_data), 400

            if len(password) < 6:
                logger.warning(f"Login attempt with password too short for user: {username}")
                response_data['message'] = 'Password must be at least 6 characters'
                return jsonify(response_data), 400

            # 3. Validate CAPTCHA
            if not captcha_input:
                logger.warning(f"Login attempt without CAPTCHA for user: {username}")
                response_data['message'] = 'CAPTCHA is required'
                return jsonify(response_data), 400

            # 4. Check brute force attempts
            if is_brute_force_attempt(username):
                logger.warning(f"Brute force attempt detected for user: {username}")
                response_data['message'] = 'Too many login attempts. Please try again later.'
                return jsonify(response_data), 429

            # 5. Verify CAPTCHA (done on client-side, but verify here too if needed)
            # The CAPTCHA validation is done on client-side, server just acknowledges
            
            # ===== Check Login Credentials =====
            
            logger.info(f"Attempting to verify credentials for user: {username}")
            login_success, user_data = check_login_success(username, password)

            if login_success and user_data:
                # Get user profile for additional info
                try:
                    profile = get_profile({'user': username})
                    logger.info(f"User profile retrieved: {profile}")
                except Exception as e:
                    logger.warning(f"Could not retrieve profile for user {username}: {e}")
                    profile = None

                # Create session
                try:
                    session['user_id'] = user_data[0] if isinstance(user_data, tuple) else user_data.get('id')
                    session['username'] = username
                    session['login_time'] = datetime.now().isoformat()
                    session.permanent = True
                    
                    logger.info(f"✅ Login successful for user: {username} at {datetime.now()}")

                    # Clear brute force counter
                    clear_brute_force_attempt(username)

                    response_data['success'] = True
                    response_data['message'] = f'Welcome {username}!'
                    response_data['redirect'] = '/dashboard'

                    return jsonify(response_data), 200
                except Exception as session_error:
                    logger.error(f"❌ Session creation error: {str(session_error)}", exc_info=True)
                    response_data['message'] = 'Session configuration error. Please contact support.'
                    return jsonify(response_data), 500

            else:
                # Log failed attempt
                log_brute_force_attempt(username)
                logger.warning(f"❌ Login failed for user: {username} - Invalid credentials at {datetime.now()}")
                response_data['message'] = 'Invalid username or password'
                
                return jsonify(response_data), 401

        except Exception as e:
            logger.error(f"❌ Error during login: {str(e)}", exc_info=True)
            response_data = {
                'success': False,
                'message': 'An error occurred during login. Please try again.'
            }
            return jsonify(response_data), 500


@login_bp.route('/dashboard')
def dashboard():
    """
    Main dashboard page after successful login
    """
    # Strict session validation - both user_id AND username must exist
    if 'user_id' not in session or 'username' not in session:
        logger.warning("Unauthorized access attempt to dashboard - invalid or missing session")
        # Clear any partial session data
        session.clear()
        return redirect(url_for('login_bp.login'))

    user_id = session.get('user_id', '')
    username = session.get('username', 'User')
    login_time = session.get('login_time', '')
    
    logger.info(f"User {username} (ID: {user_id}) accessing dashboard")
    
    return render_template('dashboard.html', user_id=user_id, username=username, login_time=login_time)


@login_bp.route('/logout', methods=['POST'])
def logout():
    """
    Handle user logout and clear session properly
    """
    from flask import make_response
    
    username = session.get('username', 'Unknown')
    user_id = session.get('user_id', 'Unknown')
    
    # Clear all session data
    session.clear()
    
    logger.info(f"User {username} (ID: {user_id}) logged out at {datetime.now()}")
    
    # Create response
    response = jsonify({
        'success': True,
        'message': 'Logged out successfully',
        'redirect': '/login'
    })
    
    # Explicitly delete session cookie
    response.delete_cookie('session', path='/')
    response.set_cookie('session', '', expires=0, path='/')
    
    return response, 200


@login_bp.route('/api/user-profile', methods=['GET'])
def get_user_profile():
    """
    Get current user profile (POST method not shown as per requirement, but can be added)
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    username = session.get('username', '')
    
    try:
        # Query user from database
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM user_dtls WHERE user = ?", (username,))
        user_data = c.fetchone()
        conn.close()

        if user_data:
            logger.info(f"User profile retrieved for: {username}")
            return jsonify({
                'success': True,
                'user_id': user_data[0],
                'username': user_data[1],
                'email': user_data[2] if len(user_data) > 2 else '',
                'login_time': session.get('login_time', '')
            }), 200
        else:
            return jsonify({'success': False, 'message': 'User not found'}), 404

    except Exception as e:
        logger.error(f"Error retrieving user profile: {str(e)}")
        return jsonify({'success': False, 'message': 'Error retrieving profile'}), 500


# ===== Helper Functions =====

def is_valid_username(username):
    """
    Validate username format
    Allowed: letters, numbers, @, _, .
    """
    pattern = r'^[a-zA-Z0-9_@.]+$'
    return re.match(pattern, username) is not None


def log_brute_force_attempt(username):
    """
    Log brute force attempt to prevent rapid login attempts
    """
    if username not in captcha_store:
        captcha_store[username] = {
            'attempts': 0,
            'last_attempt': None,
            'locked_until': None
        }
    
    captcha_store[username]['attempts'] += 1
    captcha_store[username]['last_attempt'] = datetime.now()

    # Lock account after 5 failed attempts
    if captcha_store[username]['attempts'] >= 5:
        captcha_store[username]['locked_until'] = datetime.now() + timedelta(minutes=15)
        logger.warning(f"Account {username} locked due to brute force attempts")


def is_brute_force_attempt(username):
    """
    Check if user account is locked due to brute force attempts
    """
    if username not in captcha_store:
        return False

    locked_until = captcha_store[username].get('locked_until')
    if locked_until and datetime.now() < locked_until:
        return True

    # Clear lock if time has passed
    if locked_until and datetime.now() >= locked_until:
        captcha_store[username]['locked_until'] = None
        captcha_store[username]['attempts'] = 0

    return False


def clear_brute_force_attempt(username):
    """
    Clear brute force attempts after successful login
    """
    if username in captcha_store:
        captcha_store[username] = {
            'attempts': 0,
            'last_attempt': None,
            'locked_until': None
        }



