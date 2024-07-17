import pandas as pd
import joblib

model = joblib.load('model/XGBmodel_TP25_Half_data.pkl')

def analyze_traffic(file_path='app/Extracted_Features_Data/extracted_features_top_25.csv'):
    df = pd.read_csv(file_path)

    # Handle NaN values (fill NaN with 0, you can use another strategy if needed)


    prediction=model.predict(df)

    #result[] = "Attack" if prediction == 0 else "Benign"
    print(prediction)

    return 0