from flask import Flask, request
import requests

app = Flask(__name__)

PICO_W_IP = '192.168.29.55'  # Replace with your Pico W's IP address

@app.route('/call_pico_w', methods=['GET'])
def call_pico_w():
    try:
        url = f'http://{PICO_W_IP}'
        response = requests.get(url)
        return f'Response from Pico W: {response.text}', response.status_code
    except requests.exceptions.RequestException as e:
        return f'Error: {e}', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
