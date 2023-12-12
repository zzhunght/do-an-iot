from scapy.all import *
from feture_extraction2 import Feature_extraction
import joblib
import numpy as np
import warnings
import tkinter as tk
from tkinter import messagebox
# Ignore all warnings
warnings.filterwarnings("ignore")
scaler = joblib.load('model/scaler.joblib')
label_encoder = joblib.load('model/label.joblib')
rf_model = joblib.load('model/random_forest_model_cic2.pkl')
fe = Feature_extraction()

alert_shown = False

def show_alert():
    global alert_shown
    if not alert_shown:
        alert_shown = True
        messagebox.showinfo("Alert", "This is a simple alert!")

def pcap2df(filename):
    df = fe.pcap_evaluation(filename,'csv_temp/captured_packets.csv')
    return df[1:]

def capture_and_save_packets(interface, output_file, packet_count=10, filter = ''):
    packets = sniff(iface=interface, count=packet_count, filter=filter)
    wrpcap(output_file, packets)



def model_predict(df):
    predict_val ={}

    for index, row in df.iterrows():
        data = np.array(row)
        scaled_new_data = scaler.transform([data])
        # print('scaler : ', scaled_new_data)
        # Dự đoán với mô hình
        prediction = rf_model.predict(scaled_new_data)
        # print("Predicted Label:", prediction)
        predicted_labels_original = label_encoder.inverse_transform(prediction)
        lb = predicted_labels_original[0]
        # print("Predicted Original Labels:", predicted_labels_original)
        if lb in predict_val:
            predict_val[lb] += 1
        else:
            predict_val[lb] = 1 
    
    return predict_val

if __name__ == '__main__':
    interface = 'VMware Virtual Ethernet Adapter for VMnet8'
    # ip = 'Wi-Fi'
    output_file = 'pcap_temp/captured_packets.pcap'
    filter_condition = 'src host 192.168.127.130 or dst 192.168.127.130'
    i = 0
    while True:
        print('i : >>>>>>>>>>>>>>> ', i)
        start_time = time.time()
        capture_and_save_packets(interface, output_file, packet_count=1000, filter=filter_condition)  
        elapsed_time = time.time() - start_time
        df = pcap2df(output_file)
        predict_val = model_predict(df)
        if elapsed_time < 1.5:
            for pred_lb , pred_count in predict_val.items():
                if pred_count > 300:
                    print('Phát hiện bị tấn công : ', pred_lb)
        i +=1