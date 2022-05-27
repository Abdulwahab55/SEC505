from matplotlib.pyplot import plot
import matplotlib.pyplot as plt
from sklearn import metrics
from sklearn import tree
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.ensemble import AdaBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

import numpy as np
import pandas as pd

def ML_Bot(B):

    # 
    feature_list = ["Bwd Packet Length Mean","Flow IAT Max","Flow Duration","Flow IAT Min","Flow IAT Mean","Label"]
    df=pd.read_csv("attacks_datasets/Bot.csv",usecols=feature_list)
    

    # perform the dataset initiation

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

    X_train, X_test, Y_train, y_test = train_test_split(X, y,test_size = 0.20, random_state = 2)


    clf = AdaBoostClassifier()
    clf.fit(X_train, Y_train)


    # the given captured network traffic from main.py 
    ct = B[feature_list]
    ct = ct.fillna(0)

    predict = clf.predict(ct)

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



    ct["Predicted_result"] = predict

            
    ct["Predicted_result"].value_counts().plot(kind='bar', title='Normal and Anomaly (Bot Scan) Prediction', ylabel='occurrences',
        xlabel='Prediction', figsize=(6, 5))

    plt.xticks(rotation=0)
    plt.savefig(f"/root/Desktop/Final_P/IDS/static/Bot_Attack.png")
    plt.legend(['Anomaly - 0', 'Normal - 1'])
    return ["Bot_Attack",source_ip_addr,fin_df,the_percentage_of_anomaly_traffic]