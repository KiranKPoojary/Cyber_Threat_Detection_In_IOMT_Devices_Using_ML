import pandas as pd
import xgboost as xgb

bst = xgb.Booster()  # Initialize an empty booster object
model_path = 'app/model/XGB_trained_model.model'
def analyze_traffic(file_path):

    bst.load_model(model_path)  # Load the trained model into bst
    df = pd.read_csv(file_path)

    # Handle NaN values if necessary
    df.fillna(0, inplace=True)  # Example: Fill NaN with 0

    # Make predictions
    predictions = bst.predict(xgb.DMatrix(df))
    threshold = 0.5
    class_value = 1 if predictions > threshold else 0

    print(class_value)

    result = 'Attack' if class_value == 0 else 'Benign'
    print(result)

    return result
