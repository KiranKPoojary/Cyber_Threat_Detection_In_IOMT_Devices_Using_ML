from flask import render_template,request,redirect,url_for,Flask
from capture_packet import capture_data
from flask_socketio import SocketIO,emit
import threading
import os
from predict import analyze_traffic
from extract_features import extract_features_and_save

app = Flask(__name__)
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/capture', methods=['POST'])
def capture():
    ip_address = request.form['ip_address']
    duration = int(request.form.get('duration', 60))
    thread = threading.Thread(target=capture_and_analyze, args=(ip_address,duration,socketio))
    thread.start()
    return ("Packet capture started at ",ip_address,"for a duration of ",duration)

def capture_and_analyze(ip_address,duration,socketio,interface=4):
    output_csv_path = capture_data(ip_address, duration, socketio, interface)
    if output_csv_path:
        socketio.emit('analysis_start',{'message': 'Analyzing captured data...'})
        try:
            features_csv_path = extract_features_and_save(output_csv_path, ip_address)
            if features_csv_path:
                result = analyze_traffic(features_csv_path)
                socketio.emit('analysis_complete', {'result': result})
            else:
                socketio.emit('analysis_error', {'error': 'Feature extraction failed.'})
        except Exception as e:
            socketio.emit('analysis_error', {'error': str(e)},)
    else:
        socketio.emit('capture_error', {'error': 'Error occured during packet analysis'})

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
