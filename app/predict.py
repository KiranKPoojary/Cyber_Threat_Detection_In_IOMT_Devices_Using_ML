
import pandas as pd
import xgboost as xgb
import tensorflow as tf
import numpy as np
import os
bst = xgb.Booster()  # Initialize an empty booster object
#model_path = 'app/model/CNN_trained_model.model'


def analyze_traffic():
    """
    Analyze a single 60-second traffic flow by loading extracted features,
    reshaping them, and passing them through the trained CNN model.
    """

    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Build the correct path to the CSV file relative to this directory
    file_path = os.path.join(current_dir, 'Extracted_Features_Data', 'extracted_features.csv')
    model_path = os.path.join(current_dir, 'model', 'cnn_model.keras')

    # Check if file exists
    if not os.path.exists(file_path):
        print(f"[!] CSV file not found: {file_path}")
        return
    if not os.path.exists(model_path):
        print(f"[!] Model file not found: {model_path}")
        return
    # Load the 25 features from the CSV (update these feature names as per your top 25)
    selected_features = [
        'Header-Length', 'Duration', 'Rate', 'Srate', 'syn_flag_number',
        'psh_flag_number', 'ack_flag_number', 'syn_count', 'fin_count', 'rst_count',
        'HTTPS', 'TCP', 'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size',
        'IAT', 'Number', 'Magnitude', 'Radius', 'Covariance', 'Variance', 'Weight'
    ]

    # Load the extracted features
    df = pd.read_csv(file_path)

    # Ensure only the selected 25 features are used
    input_data = df[selected_features].values

    # Handle single-sample reshape for CNN: (samples, timesteps, channels)
    input_data = input_data.reshape((input_data.shape[0], input_data.shape[1], 1))

    # Load the trained CNN model
    model = tf.keras.models.load_model(model_path)

    # Predict
    prediction = model.predict(input_data)

    # Get class labels
    predicted_class = np.argmax(prediction, axis=1)

    # Interpret prediction
    label_map = {1: 'Benign', 0: 'attack'}  # adjust based on your model training
    result = label_map.get(predicted_class[0], 'Unknown')

    print(f"[+] Prediction: {result}")
    return result


