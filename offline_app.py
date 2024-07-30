import tkinter as tk
from tkinter import ttk
import pandas as pd
import joblib  
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif
import numpy as np

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
        master.title("KDD Cup 1999 Traffic Analyzer")
        
        self.model = joblib.load('random_forest_model.sav')
        
        self.tree = ttk.Treeview(master)
        self.tree["columns"] = (
            "Packet Number", "Predicted Traffic Type"
        )
        self.tree.heading("#0", text="Packet Number")
        self.tree.heading("Predicted Traffic Type", text="Predicted Traffic Type")
        
        column_widths = {
            "Packet Number": 100,
            "Predicted Traffic Type": 150
        }
        for column, width in column_widths.items():
            self.tree.column(column, width=width)

        scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(expand=True, fill="both")
        
        self.label_encoder = LabelEncoder()
        self.label_encoder_fitted = False
        self.packet_number = 1

        self.predict_traffic_from_dataset()

    def preprocess_dataset(self):
        imputer = SimpleImputer(strategy='mean')
        url = "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz"
        columns = [
            "duration", "protocol_type", "service", "src_bytes", "dst_bytes", "land", 
            "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", 
            "num_compromised", "root_shell", "su_attempted", "num_root", 
            "num_file_creations", "num_shells", "num_access_files", 
            "num_outbound_cmds", "is_host_login", "is_guest_login", "count", 
            "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", 
            "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
            "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
            "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", 
            "dst_host_serror_rate", "dst_host_srv_serror_rate", 
            "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
            "target", "flag"
        ]
        df = pd.read_csv(url, names=columns)

        continuous_columns = []
        for column in df.columns:
            if df[column].dtype in ['int64', 'float64'] and column != 'target':
                continuous_columns.append(column)

        categorical_columns = [col for col in df.columns if col not in continuous_columns and col != 'target']
        df = pd.get_dummies(df, columns=categorical_columns, drop_first=True)

        selector = SelectKBest(score_func=f_classif, k=127)
        X_new = selector.fit_transform(df.drop(columns=['target']), df['target'])

        df_selected = pd.DataFrame(X_new, columns=[df.columns[i] for i in selector.get_support(indices=True)])
        df_selected['target'] = df['target']

        imputer = SimpleImputer(strategy='mean')
        df_imputed = imputer.fit_transform(df_selected)

        return df_imputed


    def predict_traffic_from_dataset(self):

        preprocessed_dataset = self.preprocess_dataset()

        predictions = self.model.predict(preprocessed_dataset)  

        for i, prediction in enumerate(predictions):

            if prediction == 0:
                predicted_traffic_type = "Normal"

            elif prediction == 1:
                predicted_traffic_type = "DDoS"
            
            elif prediction ==2:
                predicted_traffic_type = "u2r"
            
            elif prediction == 3:
                predicted_traffic_type = "r2l"

            else :
                predicted_traffic_type = "probe"

            self.tree.insert("", "end", values=(self.packet_number, predicted_traffic_type))
            self.packet_number += 1 
        
class SelectKBest:
    def __init__(self, score_func=f_classif, k=127):
        self.score_func = score_func
        self.k = k
        self.selected_features_ = None

    def fit(self, X, y):
        scores = []
        for i in range(X.shape[1]):
            score = self.score_func(X[:, i].reshape(-1, 1), y)
            scores.append((i, score))
        scores.sort(key=lambda x: x[1], reverse=True)
        self.selected_features_ = [x[0] for x in scores[:self.k]]

    def fit_transform(self, X, y):
        X = np.atleast_2d(X)  
        y = np.ravel(y)  
        self.fit(X, y)
        return self.transform(X)

    def transform(self, X):
        return X[:, self.selected_features_]
        

root = tk.Tk()
app = TrafficAnalyzerApp(root)

root.mainloop()
