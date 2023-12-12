import joblib
from sklearn.preprocessing import StandardScaler
import numpy as np

scaler = joblib.load('model/scaler.joblib')
label_encoder = joblib.load('model/label.joblib')
print(label_encoder.classes_)
rf_model = joblib.load('model/random_forest_model_cic2.pkl')


new_data = [0,54,6,64,105.4573889,105.4573889,0,1,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0,1,1,567,54,54,54,0,54,83089959.47,9.5,10.39230485,0,0,0,141.55]
# Chuẩn hóa dữ liệu mới
scaled_new_data = scaler.transform([new_data])

# print('scaler : ', scaled_new_data)
# Dự đoán với mô hình
prediction = rf_model.predict(scaled_new_data)

print("Predicted Label:", prediction)
predicted_labels_original = label_encoder.inverse_transform(prediction)

print("Predicted Original Labels:", predicted_labels_original)