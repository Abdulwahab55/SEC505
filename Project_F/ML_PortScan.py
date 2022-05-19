from sklearn import metrics
from sklearn import tree
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
import matplotlib.pyplot as plt
from sklearn.metrics import f1_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score


import matplotlib.pyplot as plt
import numpy as np
import os
import pandas as pd
import csv
import time
import warnings
import math

def ML_PortScan(B):


    feature_list = ["Flow Bytes/s","Total Length of Fwd Packets","Fwd IAT Total","Flow Duration","Label"]
    df=pd.read_csv("attacks_datasets\PortScan.csv",usecols=feature_list)


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


    clf = DecisionTreeClassifier(max_depth=5,criterion="entropy")

    clf.fit(X_train, y_train)


    ct = B[feature_list]
    ct = ct.fillna(0)

    predict =clf.predict(ct)

    the_predicted_normal_traffic_occorance = np.count_nonzero(predict == 1)
    the_predicted_anomaly_traffic_occorance = np.count_nonzero(predict == 0)

    the_percentage_of_normal_traffic = round(100 - ((the_predicted_anomaly_traffic_occorance/ct.shape[0]) * 100),2)

    print(f"""
    normal network flow is {the_predicted_normal_traffic_occorance}
    anomly network flow is {the_predicted_anomaly_traffic_occorance}
    the tested traffic is clear with {the_percentage_of_normal_traffic}% with Port_Scan predition ML
    """)

    ct["Predicted_result"] = predict
    ct["Predicted_result"].value_counts().plot(kind='bar', title='Normal and Anomaly (Port Scan) Prediction', ylabel='occurrences',
        xlabel='Prediction', figsize=(6, 5))
    # pr=precision_score(y_test, predict, average='macro')
    # print(pr)
    plt.xticks(rotation=0)
    plt.savefig(f"Figures\\Port_Scan_Plot.png")