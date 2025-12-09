import pyotp
import json
import requests
from kiteconnect import KiteConnect
from api_urls import LOGIN_URL, TWOFA_URL
from config import ACCESS_TOKEN_FILE

def autologin_zerodha(user):
    session = requests.Session()

    # Step 1: Login with user_id and password
    response = session.post(LOGIN_URL, data={'user_id': user['kite_username'], 'password': user['kite_password']})
    request_id = json.loads(response.text)['data']['request_id']

    # Step 2: Two-factor authentication
    twofa_pin = pyotp.TOTP(user['kite_totp_token']).now()
    session.post(
        TWOFA_URL,
        data={
            'user_id': user['kite_username'],
            'request_id': request_id,
            'twofa_value': twofa_pin,
            'twofa_type': 'totp'
        }
    )

    # Step 3: Generate request_token and access_token
    kite = KiteConnect(api_key=user['kite_api_key'])
    kite_url = kite.login_url()
    print("[INFO] Kite login URL:", kite_url)

    try:
        session.get(kite_url)
    except Exception as e:
        e_msg = str(e)
        if 'request_token=' in e_msg:
            request_token = e_msg.split('request_token=')[1].split(' ')[0].split('&action')[0]
            print('[INFO] Successful Login with Request Token:', request_token)

            access_token = kite.generate_session(request_token, user['kite_api_secret'])['access_token']
            kite.set_access_token(access_token)

            # Prepare token data
            token_data = {
                "access_token": access_token,
                "api_key": user['kite_api_key'],
                "api_secret": user['kite_api_secret'],
                "username": user['kite_username']
            }
            FILE = user['user'] + "_" + ACCESS_TOKEN_FILE
            # ✅ Save to JSON
            with open(FILE, "w") as f:
                json.dump(token_data, f, indent=2)
            print(f"[INFO] Token saved to file: {ACCESS_TOKEN_FILE}")

            # ✅ Save to DB
            # save_token_to_db(token_data, DBNAME)
            # print(f"[INFO] Token also saved to database: {DBNAME}")

            return access_token
        else:
            print("[ERROR] Could not extract request_token from exception.")
            return None

def do_login(user):

    result = autologin_zerodha(user)

    if result:
        print(f"[✅] Access token generated and saved successfully for {user['user']}.")
    else:
        print(f"[❌] Login failed for {user['user']}.")
    

