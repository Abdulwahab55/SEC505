from ML_DoS_SL import ML_DS_SL
from ML_DoS_SHT import ML_DS_SHT
from ML_DoS_HL import ML_DS_HL
from ML_DoS_GE import ML_DS_GE
from calendar import c
from logging import captureWarnings
import os
from numpy import true_divide
import pandas as pd
from ML_Bot import ML_Bot
from ML_DOS_DDOS import ML_DOS
from ML_FTP import ML_FTP
from ML_Infilteration import ML_Infiltr
from ML_PortScan import ML_PortScan

from ML_SSH import ML_SSH
from ML_Web import ML_Web
import time
from datetime import datetime
def main():



    
    # this main app is read the traffic from captured pcap and do anomly analysis
    # After the network traffic is been captured and converted to csv, this application is marking the data as tested first and perform IDS testing to to detect any abnormal behaviors

    while True:
        os.system("dumpcap -i eth1 -a duration:60 -w Network_traffic/captured.pcap")
        files = os.listdir("Network_traffic")

        if files: # check if the new file exists
            os.system(f"./cfm Network_traffic/{files[0]} flow_data/") # convert pcap file into flow-traffic file using CICFlowMeter
            os.system(f"sed -i '1d' flow_data/*")
            flow_file = os.listdir("flow_data")
            if flow_file:
                captured_traffic = prepare_network_traffic(flow_file[0])
                ML(captured_traffic)
                os.remove(f"flow_data/{flow_file[0]}")
            os.remove(f"Network_traffic/{files[0]}")

    



def prepare_network_traffic(file_name):
    
    # static variables
    live_traffic_labels = ["Flow ID","Source IP","Source Port","Destination IP","Destination Port","Protocol","Timestamp","Flow Duration","Total Fwd Packets",
"Total Backward Packets","Total Length of Fwd Packets","Total Length of Bwd Packets","Fwd Packet Length Max","Fwd Packet Length Min",
"Fwd Packet Length Mean","Fwd Packet Length Std","Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std",
"Flow Bytes/s","Flow Packets/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min","Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max",
"Fwd IAT Min","Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min","Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags",
"Fwd Header Length","Bwd Header Length","Fwd Packets/s","Bwd Packets/s","Min Packet Length","Max Packet Length","Packet Length Mean","Packet Length Std",
"Packet Length Variance","FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count","URG Flag Count","CWE Flag Count",
"ECE Flag Count","Down/Up Ratio","Average Packet Size","Avg Fwd Segment Size","Avg Bwd Segment Size","Fwd Avg Bytes/Bulk",
"Fwd Avg Packets/Bulk","Fwd Avg Bulk Rate","Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk","Bwd Avg Bulk Rate","Subflow Fwd Packets","Subflow Fwd Bytes",
"Subflow Bwd Packets","Subflow Bwd Bytes","Init_Win_bytes_forward","Init_Win_bytes_backward","act_data_pkt_fwd",
"min_seg_size_forward","Active Mean","Active Std","Active Max","Active Min","Idle Mean","Idle Std","Idle Max","Idle Min","Label"]
   
    captured_traffic = pd.read_csv(f"flow_data/{file_name}",names=live_traffic_labels)
    captured_traffic = captured_traffic.round(decimals=2)
    captured_traffic = captured_traffic.fillna(0)

    return captured_traffic # return the new DataFrame

def ML(captured_traffic):
    result_list = []
    fin_severe_max = ''

    result_list.append(ML_Bot(captured_traffic))
    time.sleep(2)
    result_list.append(ML_SSH(captured_traffic))
    time.sleep(2)
    result_list.append(ML_Web(captured_traffic))
    time.sleep(2)
    result_list.append(ML_FTP(captured_traffic))
    time.sleep(2)
    result_list.append(ML_DS_GE(captured_traffic))
    time.sleep(2)
    result_list.append(ML_PortScan(captured_traffic))
    most_severe_attack = {} # this dictionary holds each attack with its predicted anomaly infection percentage
    for i in result_list:
        if i[-1] > 10: # check the return percentage for each attack, if its bigger than 10% save the anomaly data for further investigation.
            most_severe_attack[i[0]] = i[-1]
            date = datetime.now().strftime('%Y_%m_%d-%I:%M:%S_%p')
            i[2].to_csv(f"Reports/anomaly_saved_traffic_{i[0]}_{date}.csv",encoding="utf-8",index=False)
    if most_severe_attack:
        fin_severe_max = max(most_severe_attack,key=most_severe_attack.get)

        if int(most_severe_attack[fin_severe_max]) > 0:
            for i in result_list:
                if fin_severe_max in i[0]:
                    # load the tamplate of the file
                    file_in = open(f"templates/{fin_severe_max}.txt",'r')
                    filedata = file_in.read()

                    filedata = filedata.replace("SOURCEE_IPP",f"{i[1]}") # add the Source-IP of the anomaly-traffic.
                    filedata = filedata.replace("PERCENTAGEE",f"{i[-1]}%") # add the percentage of the anomaly traffic.

                    file_out = open("/root/Desktop/Final_P/IDS/static/Attack_Details.txt",'w')
                    file_out.write(filedata)

                    file_in.close()
                    file_out.close()
                    print(fin_severe_max)
                    # Set the figure of the most predicted severe anomaly traffic
                    os.system(f"cp '/root/Desktop/Final_P/IDS/static/{fin_severe_max}.png' /root/Desktop/Final_P/IDS/static/Attack_pic.png")

                # print(f"Most in {fin_severe_max} with {most_severe_attack[fin_severe_max]}")
    
    
main()
