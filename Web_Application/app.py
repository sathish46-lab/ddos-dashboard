from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd

app = Flask(__name__)

# Load the trained model
model = joblib.load('rf_model.pkl')  # Adjust path if needed

@app.route('/')
def home():
    return render_template('index.html')  # Use an HTML template

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json  # Expect JSON input
    df = pd.DataFrame([data])  # Convert to DataFrame
    prediction = model.predict(df)[0]  # Predict using ML model
    return jsonify({'prediction': int(prediction)})  # Return result

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
