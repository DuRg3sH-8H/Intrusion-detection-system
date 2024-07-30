import tkinter as tk
from tkinter import ttk
import threading
import pandas as pd
import joblib
from scapy.all import sniff
from scapy.layers.inet import IP,TCP,UDP
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder
from scapy.packet import Raw

model = joblib.load('random_forest_model.sav')

attacks_types = { 
    0: 'normal', 
    1: 'probe',
    2: 'u2r', 
    3: 'r2l', 
    4: 'dos'
}


class TrafficAnalyzerApp:
    def __init__(self, master):
        self.master = master
        master.title("Live Traffic Analyzer")

        self.tree = ttk.Treeview(master)
        self.tree["columns"] = (
            "Packet Number", "Source IP", "Source Port", "Destination IP", "Destination Port",
            "Protocol", "Packet Size", "Flags",  "Payload", "Predicted Traffic Type"
        )
        self.tree.heading("#0", text="Packet Number")
        self.tree.heading("Source IP", text="Source IP")
        self.tree.heading("Source Port", text="Source Port")
        self.tree.heading("Destination IP", text="Destination IP")
        self.tree.heading("Destination Port", text="Destination Port")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Packet Size", text="Packet Size")
        self.tree.heading("Flags", text="Flags")
        self.tree.heading("Payload", text="Payload")
        self.tree.heading("Predicted Traffic Type", text="Predicted Traffic Type")

        column_widths = {
            "Packet Number": 100, "Source IP": 150, "Source Port": 100,
            "Destination IP": 150, "Destination Port": 120, "Protocol": 100,
            "Packet Size": 100, "Flags": 100,
            "Payload": 200, "Predicted Traffic Type": 150
        }
        for column, width in column_widths.items():
            self.tree.column(column, width=width)

        self.tree.pack(expand=True, fill="both")
        

        self.start_button = tk.Button(master, text="Start Capture", command=self.start_capture)
        self.start_button.pack(pady=5)
        

        self.stop_button = tk.Button(master, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.capture_thread = None
        self.capture_running = False

        self.label_encoder = LabelEncoder()
        self.label_encoder_fitted = False

        self.packet_number = 1
        

    def preprocess_traffic(self, packet):
        imputer = SimpleImputer(strategy='mean')
        duration = 0
        protocol_type = packet[IP].proto
        service = 'unknown'
        src_bytes = len(packet)
        dst_bytes = 0
        land = 0
        wrong_fragment = 0
        urgent = 0
        hot = 0
        num_failed_logins = 0
        logged_in = 0
        num_compromised = 0
        root_shell = 0
        su_attempted = 0
        num_root = 0
        num_file_creations = 0
        num_shells = 0
        num_access_files = 0
        num_outbound_cmds = 0
        is_host_login = 0
        is_guest_login = 0
        count = 0
        srv_count = 0
        serror_rate = 0.0
        srv_serror_rate = 0.0
        rerror_rate = 0.0
        srv_rerror_rate = 0.0
        same_srv_rate = 0.0
        diff_srv_rate = 0.0  
        srv_diff_host_rate = 0.0 
        dst_host_count = 0  
        dst_host_srv_count = 0  
        dst_host_same_srv_rate = 0.0  
        dst_host_diff_srv_rate = 0.0  
        dst_host_same_src_port_rate = 0.0  
        dst_host_srv_diff_host_rate = 0.0  
        dst_host_serror_rate = 0.0  
        dst_host_srv_serror_rate = 0.0  
        dst_host_rerror_rate = 0.0  
        dst_host_srv_rerror_rate = 0.0  
        

        df = pd.DataFrame({
            "duration": [duration],
            "protocol_type": [protocol_type],
            "service": [service],
            "src_bytes": [src_bytes],
            "dst_bytes": [dst_bytes],
            "land": [land],
            "wrong_fragment": [wrong_fragment],
            "urgent": [urgent],
            "hot": [hot],
            "num_failed_logins": [num_failed_logins],
            "logged_in": [logged_in],
            "num_compromised": [num_compromised],
            "root_shell": [root_shell],
            "su_attempted": [su_attempted],
            "num_root": [num_root],
            "num_file_creations": [num_file_creations],
            "num_shells": [num_shells],
            "num_access_files": [num_access_files],
            "num_outbound_cmds": [num_outbound_cmds],
            "is_host_login": [is_host_login],
            "is_guest_login": [is_guest_login],
            "count": [count],
            "srv_count": [srv_count],
            "serror_rate": [serror_rate],
            "srv_serror_rate": [srv_serror_rate],
            "rerror_rate": [rerror_rate],
            "srv_rerror_rate": [srv_rerror_rate],
            "same_srv_rate": [same_srv_rate],
            "diff_srv_rate": [diff_srv_rate],
            "srv_diff_host_rate": [srv_diff_host_rate],
            "dst_host_count": [dst_host_count],
            "dst_host_srv_count": [dst_host_srv_count],
            "dst_host_same_srv_rate": [dst_host_same_srv_rate],
            "dst_host_diff_srv_rate": [dst_host_diff_srv_rate],
            "dst_host_same_src_port_rate": [dst_host_same_src_port_rate],
            "dst_host_srv_diff_host_rate": [dst_host_srv_diff_host_rate],
            "dst_host_serror_rate": [dst_host_serror_rate],
            "dst_host_srv_serror_rate": [dst_host_srv_serror_rate],
            "dst_host_rerror_rate": [dst_host_rerror_rate],
            "dst_host_srv_rerror_rate": [dst_host_srv_rerror_rate],
            "target": [0],
            "flag": ["unknown"]
        })

        df = pd.get_dummies(df, columns=['service'], drop_first=True)

        df = pd.get_dummies(df, columns=['flag'], drop_first=True)

        df = pd.get_dummies(df, columns=['protocol_type'], drop_first=True)

        df['src_bytes'] = pd.to_numeric(df['src_bytes'], errors='coerce')

        target_columns = [col for col in df.columns if col.startswith('target_')]
        if len(target_columns) > 0:
            df['target'] = df[target_columns].idxmax(axis=1).apply(lambda x: x.split('_')[1])
            df = df.drop(columns=target_columns)

        label_encoder = LabelEncoder()
        if not self.label_encoder_fitted:
            self.label_encoder.fit(df['target'])
            self.label_encoder_fitted = True
        
        if not hasattr(self.label_encoder, 'classes_'):
            self.label_encoder.fit(df['target'])
        df['target'] = label_encoder.fit_transform(df['target'])
        
        if hasattr(imputer, 'statistics_'):
            if imputer.statistics_ is not None:
                live_traffic_imputed = imputer.transform(df)
            else:
                live_traffic_imputed = df
        else:
            imputer.fit(df) 
            live_traffic_imputed = imputer.transform(df)
        
        return live_traffic_imputed


    def predict_traffic(self, packet):

        preprocessed_traffic = self.preprocess_traffic(packet)
        
        prediction = model.predict(preprocessed_traffic)
        
        return prediction

    def handle_packet(self, packet):
        if IP in packet:
            
            packet_size = len(packet) 
            flags = packet.sprintf('%flags%') if packet.haslayer(TCP) else "N/A" 
            
            payload = packet.load if hasattr(packet, 'load') else "N/A" 
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[IP].sport if TCP in packet else packet[IP].sport if UDP in packet else "N/A"
            dst_port = packet[IP].dport if TCP in packet else packet[IP].dport if UDP in packet else "N/A"
            protocol = packet[IP].proto
            protocol_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "ICMP" if protocol == 1 else "Other"
            
            
          

            for i, prediction in enumerate(predictions):
                if prediction == 0:
                    predicted_traffic_type = "Normal"
                elif prediction == 1:
                    predicted_traffic_type = "DDoS"
                elif prediction == 2:
                    predicted_traffic_type = "u2r"
                elif prediction == 3:
                    predicted_traffic_type = "r2l"
                else:
                    predicted_traffic_type = "probe"

                self.tree.insert("", "end", values=(self.packet_number, src_ip, src_port, dst_ip, dst_port, protocol_name, packet_size,flags, payload,predicted_traffic_type))
                self.packet_number += 1
                self.tree.yview_moveto(1.0)


    def start_capture(self):
        self.tree.delete(*self.tree.get_children())  
        self.packet_number = 1
        self.capture_running = True
        self.capture_thread = threading.Thread(target=self.capture_traffic)
        self.capture_thread.start()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_capture(self):
        self.capture_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def capture_traffic(self):
        def packet_callback(packet):
            if self.capture_running:
                self.handle_packet(packet)
            else:
                return


        sniff(prn=packet_callback, store=0)

root = tk.Tk()
app = TrafficAnalyzerApp(root)
root.mainloop()
