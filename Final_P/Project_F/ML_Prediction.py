# this application is designed for ML prediction
# this application will receive two arguements, first is captured data, and second is list of classifiers and corresponding features list
from matplotlib import pyplot as plt
import numpy as np


def ML_Prediction(ctt,classifiers):
    features={"Bot":["Bwd Packet Length Mean","Flow IAT Max","Flow Duration","Flow IAT Min","Label"],
    "DoS GoldenEye":["Flow IAT Max","Bwd Packet Length Std","Flow IAT Min","Total Backward Packets","Label"],
    "DoS Hulk":["Bwd Packet Length Std","Fwd Packet Length Std","Fwd Packet Length Max","Flow IAT Min","Label"],
    "DoS Slowhttptest":["Flow IAT Mean","Fwd Packet Length Min","Bwd Packet Length Mean","Total Length of Bwd Packets","Label"],
    "DoS slowloris":["Flow IAT Mean","Total Length of Bwd Packets","Bwd Packet Length Mean","Total Fwd Packets","Label"],
    "FTP-Patator":["Fwd Packet Length Max","Fwd Packet Length Std","Fwd Packet Length Mean","Bwd Packet Length Std","Label"],
    "Infiltration":["Fwd Packet Length Max","Fwd Packet Length Mean","Flow Duration","Total Length of Fwd Packets","Label"],
    "PortScan":["Flow Bytes/s","Total Length of Fwd Packets","Fwd IAT Total","Flow Duration","Label"],
    "SSH-Patator":["Fwd Packet Length Max","Flow Duration","Flow IAT Max","Total Length of Fwd Packets","Label"],
    "Web Attack":["Bwd Packet Length Std","Total Length of Fwd Packets","Flow Bytes/s","Flow IAT Max","Label"]}

    classifiers_pointer = 0
    for i in features:
        features_list = features[i]
        features_list.remove('Label')
        ct = ctt[features_list]
        ct = ct.fillna(0)
        clf = classifiers[classifiers_pointer]
        classifiers_pointer = classifiers_pointer + 1
        clf.predict(ct)

        predict =clf.predict(ct)
        the_predicted_normal_traffic_occorance = np.count_nonzero(predict == 1)
        the_predicted_anomaly_traffic_occorance = np.count_nonzero(predict == 0)

        the_percentage_of_normal_traffic = round(100 - ((the_predicted_anomaly_traffic_occorance/ct.shape[0]) * 100),2)

        print(f"""
    normal network flow is {the_predicted_normal_traffic_occorance}
    anomly network flow is {the_predicted_anomaly_traffic_occorance}
    the tested traffic is clear with {the_percentage_of_normal_traffic}% with {i} predition ML
        """)
        ct["Predicted_result"] = predict
        ct["Predicted_result"].value_counts().plot(kind='bar', title=f'Normal and Anomaly ({i}) Prediction', ylabel='occurrences',
        xlabel='Prediction', figsize=(6, 5))
        plt.xticks(rotation=0)
        plt.savefig(f"Figures_2/{i}.png")
