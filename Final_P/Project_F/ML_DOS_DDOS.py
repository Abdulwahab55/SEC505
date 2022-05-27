import numpy as np
from sklearn import metrics
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
import matplotlib.pyplot as plt

import os
import pandas as pd

def ML_DOS(B):

    csv_files=os.listdir("attacks_datasets/DOS_DDOS")# CSV files names: #The names of the files in the attacks folder are taken and assigned to a list (csv_files).
    path="./attacks_datasets/DOS_DDOS/"


    features={
    "DoS GoldenEye":["Flow IAT Max","Bwd Packet Length Std","Flow IAT Min","Total Backward Packets","Flow IAT Mean","Label"],
    "DoS Hulk":["Bwd Packet Length Std","Fwd Packet Length Std","Fwd Packet Length Max","Flow IAT Min","Flow IAT Mean","Label"],
    "DoS Slowhttptest":["Flow IAT Mean","Fwd Packet Length Min","Bwd Packet Length Mean","Total Length of Bwd Packets","Label"],
    "DoS slowloris":["Flow IAT Mean","Total Length of Bwd Packets","Bwd Packet Length Mean","Total Fwd Packets","Label"],
    }



    for j in csv_files: #this loop runs on the list containing the filenames.Operations are repeated for all attack files
        a=[]
        
        feature_list=list(features[j[0:-4]])
        df=pd.read_csv(path+j,usecols=feature_list)#read an attack file.
        df=df.fillna(0)
        attack_or_not=[]
        for i in df["Label"]: #it changes the normal label to "1" and the attack tag to "0" for use in the machine learning algorithm
            
            if i =="BENIGN":
                attack_or_not.append(1)
            else:
                attack_or_not.append(0)           
        df["Label"]=attack_or_not

        
        y = df["Label"] #this section separates the label and the data into two separate pieces, as Label=y Data=X 
        del df["Label"]
        feature_list.remove('Label')
        X = df[feature_list]

        X_train, X_test, y_train, y_test = train_test_split(X, y,test_size = 0.20, random_state = 10)

        clf = DecisionTreeClassifier(max_depth=5,criterion="entropy")

        ct = B[feature_list]
        ct = ct.fillna(0)

        clf.fit(X_train, y_train)
        predict =clf.predict(ct)
        
        B["Predicted_result"] = predict

        normal_trf_ocr = np.count_nonzero(predict == 1)
        anomaly_trf_ocr = np.count_nonzero(predict == 0)
        Total = normal_trf_ocr + anomaly_trf_ocr

        the_percentage_of_anomaly_traffic = round((anomaly_trf_ocr / Total) * 100,2)

        source_ip_addr = 0
        fin_df = pd.DataFrame()    
        # Get the Source IP of the anomaly traffic
        if anomaly_trf_ocr > 0:
            fin_df = B[B['Predicted_result'] == 0]
            fin_df.drop('Label', inplace=True,axis=1)
            source_ip_addr = fin_df['Source IP'].value_counts().idxmax()
        else:
            pass
    #     print(f"""
    # normal network flow is {normal_trf_ocr}
    # anomly network flow is {anomaly_trf_ocr}
    # the tested traffic is anomaly with {the_percentage_of_anomaly_traffic}% with DoS_Scan predition ML
    #     """)

        ct["Predicted_result"] = predict
        # attack_or_not_back = []
        # for i in ct["Predicted_result"]:
    
        #     if i == 1:
        #         attack_or_not_back.append("Normal")
        #     else:
        #         attack_or_not_back.append("Anomaly") 
        # ct["Predicted_result"] = attack_or_not_back
        ct["Predicted_result"].value_counts().plot(kind='bar', title=f'Normal and Anomaly ({j[0:-4]}) Prediction', ylabel='occurrences',
        xlabel='Prediction', figsize=(6, 5))
        # pr=precision_score(y_test, predict, average='macro')
        # print(pr)
        plt.xticks(rotation=0)
        plt.savefig(f"/root/Desktop/Final_P/IDS/static/{j[0:-4]}.png")
        return [f"{j[0:-4]}",source_ip_addr,fin_df,the_percentage_of_anomaly_traffic]
