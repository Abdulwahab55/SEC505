# This application is for ML initialization that is responsible for preparing the dataset for each listed attack and perform data fitting and return ML model for each.

import os
from sklearn import tree
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.model_selection import train_test_split
import numpy as np
import pandas as pd

def ML_Initialization():
    
    # list the attack_dataset directory
    files_list = os.listdir("attacks_dataset_2")
    path = "attacks_dataset_2/"

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

    # list_of_clf = [AdaBoostClassifier(),tree.DecisionTreeClassifier(max_depth=5,criterion="entropy"),tree.DecisionTreeClassifier(max_depth=5,criterion="entropy"),tree.DecisionTreeClassifier(max_depth=5,criterion="entropy"),tree.DecisionTreeClassifier(max_depth=5,criterion="entropy"),AdaBoostClassifier(),RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1),tree.DecisionTreeClassifier(max_depth=5,criterion="entropy"),RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1),RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1)]

    classifier_list = []

    for j in files_list:
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

        clf = tree.DecisionTreeClassifier(max_depth=5,criterion="entropy")

        classifier_list.append(clf.fit(X_train.values, y_train))
    
    return classifier_list
    
    # print(len(classifier_list))


ML_Initialization()