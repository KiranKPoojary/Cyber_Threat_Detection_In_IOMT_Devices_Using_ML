from flask import render_template,request,redirect,url_for,Flask,jsonify
from capture_packet import capture_data
from flask_socketio import SocketIO,emit
import threading
import pandas as pd
import os
from predict import analyze_traffic
from extract_features import extract_features_and_save

app = Flask(__name__)
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/capture', methods=['POST'])
def capture():
    ip_address = request.form['ip_address']
    duration = int(request.form.get('duration', 60))
    thread = threading.Thread(target=capture_and_analyze, args=(ip_address,duration,socketio))
    thread.start()
    return jsonify({
        "message": "Packet capture started",
        "ip_address": ip_address,
        "duration": duration
    }), 200

@app.route('/data')
def get_data():
    df = pd.read_csv('app/Extracted_Features_Data/extracted_features.csv')

    # Select the first 50 rows for better visualization
    df = df.head(50)

    # Convert data to JSON format
    data = {
        "header_length": df["Header-Length"].tolist(),
        "duration": df["Duration"].tolist(),
        "rate": df["Rate"].tolist(),
        "srate": df["Srate"].tolist(),
        "syn_flag_number": df["syn_flag_number"].tolist(),
        "psh_flag_number": df["psh_flag_number"].tolist(),
        "ack_flag_number": df["ack_flag_number"].tolist(),
        "syn_count": df["syn_count"].tolist(),
        "fin_count": df["fin_count"].tolist(),
        "rst_count": df["rst_count"].tolist(),
        "https": df["HTTPS"].tolist(),
        "tcp": df["TCP"].tolist(),
        "tot_sum": df["Tot sum"].tolist(),
        "min": df["Min"].tolist(),
        "max": df["Max"].tolist(),
        "avg": df["AVG"].tolist(),
        "std": df["Std"].tolist(),
        "tot_size": df["Tot size"].tolist(),
        "number": df["Number"].tolist(),
        "magnitude": df["Magnitude"].tolist(),
        "radius": df["Radius"].tolist(),
        "covariance": df["Covariance"].tolist(),
        "variance": df["Variance"].tolist(),
        "weight": df["Weight"].tolist()
    }
    return jsonify(data)


def capture_and_analyze(ip_address,duration,socketio,interface=4):
    output_csv_path = capture_data(ip_address, duration, socketio, interface)
    if output_csv_path:
        socketio.emit('analysis_start', {'message': 'Analyzing captured data...'})
        try:
            features_csv_path = extract_features_and_save(output_csv_path, ip_address)
            if features_csv_path:
                result = analyze_traffic()
                socketio.emit('analysis_complete', {'result': result})
            else:
                socketio.emit('analysis_error', {'error': 'Feature extraction failed.'})
        except Exception as e:
            socketio.emit('analysis_error', {'error': str(e)},)
    else:
        socketio.emit('capture_error', {'error': 'Error occured during packet analysis'})

if __name__ == '__main__':
    #threading.Thread(target=send_feature_updates, daemon=True).start()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
