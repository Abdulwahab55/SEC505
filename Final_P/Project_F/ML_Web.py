from matplotlib import pyplot as plt
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

def ML_Web(B):
    feature_list = ["Destination Port","Flow Packets/s","Flow IAT Max","Total Length of Fwd Packets","Flow Bytes/s","Label"]
    df=pd.read_csv("attacks_datasets/Web Attack.csv",usecols=feature_list)


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


    clf = RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1)
    clf.fit(X_train, Y_train)

    

    ct = B[feature_list]
    ct = ct.fillna(0)

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
    # print(f"""
    # normal network flow is {normal_trf_ocr}
    # anomly network flow is {anomaly_trf_ocr}
    # the tested traffic is anomaly with {the_percentage_of_anomaly_traffic}% with Web_Attack_Scan predition ML
    # """)

    ct["Predicted_result"] = predict
    # attack_or_not_back = []
    # for i in ct["Predicted_result"]:
        
    #     if i == 1:
    #         attack_or_not_back.append("Normal")
    #     else:
    #         attack_or_not_back.append("Anomaly")
    # ct["Predicted_result"] = attack_or_not_back
    ct["Predicted_result"].value_counts().plot(kind='bar', title='Normal and Anomaly (Web Attack) Prediction', ylabel='occurrences',
        xlabel='Prediction', figsize=(6, 5))

    plt.xticks(rotation=0)
    plt.savefig(f"/root/Desktop/Final_P/IDS/static/Web Attack.png")
    plt.legend(['Anomaly - 0', 'Normal - 1'])
    # pr=precision_score(y_test, predict, average='macro')
    # print(pr)

    return ["Web Attack",source_ip_addr,fin_df,the_percentage_of_anomaly_traffic]