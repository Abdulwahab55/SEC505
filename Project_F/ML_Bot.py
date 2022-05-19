from matplotlib.pyplot import plot
import matplotlib.pyplot as plt
from sklearn import metrics
from sklearn import tree
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.ensemble import AdaBoostClassifier
from sklearn.model_selection import train_test_split
import numpy as np
import pandas as pd

def ML_Bot(B):

    # 
    feature_list = ["Bwd Packet Length Mean","Flow IAT Max","Flow Duration","Flow IAT Min","Label"]
    df=pd.read_csv("attacks_datasets\Bot.csv",usecols=feature_list)


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

    X_train, X_test, y_train, y_test = train_test_split(X, y,test_size = 0.20, random_state = 2)


    clf = AdaBoostClassifier()
    clf.fit(X_train, y_train)


    # the given captured network traffic from main.py 
    ct = B[feature_list]
    ct = ct.fillna(0)

    predict =clf.predict(ct)

    ct["Predicted_result"] = predict

    the_predicted_normal_traffic_occorance = np.count_nonzero(predict == 1)
    the_predicted_anomaly_traffic_occorance = np.count_nonzero(predict == 0)

    the_percentage_of_normal_traffic = round(100 - ((the_predicted_anomaly_traffic_occorance/ct.shape[0]) * 100),2)

    print(f"""
    normal network flow is {the_predicted_normal_traffic_occorance}
    anomly network flow is {the_predicted_anomaly_traffic_occorance}
    the tested traffic is clear with {the_percentage_of_normal_traffic}% with Bot_Scan predition ML
    """)

    ct["Predicted_result"] = predict
    ct["Predicted_result"].value_counts().plot(kind='bar', title='Normal and Anomaly (Bot Scan) Prediction', ylabel='occurrences',
        xlabel='Prediction', figsize=(6, 5))
    # pr=precision_score(y_test, predict, average='macro')
    # print(pr)
    plt.xticks(rotation=0)
    plt.savefig(f"Figures\\Bot_analysis_Plot.png")