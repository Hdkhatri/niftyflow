import requests
import json

#old one 
#url = f'https://api.telegram.org/bot{TOKEN}/getUpdates'
# res = requests.get(url)
# print(json.dumps(res.json(), indent=4))


def send_telegram_message(message, CHAT_ID, TOKEN):
    url = f'https://api.telegram.org/bot{TOKEN}/sendMessage'
    data = {
        'chat_id': CHAT_ID,
        'text': message
    }
    response = requests.post(url, data=data)
    

