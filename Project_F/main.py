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
from ML_heartbleed import ML_Heartbleed
import time
def main():



    
    # this main app is read the traffic from captured pcap and do anomly analysis
    # After the network traffic is been captured and converted to csv, this application is marking the data as tested first and perform IDS testing to to detect any abnormal behaviors

    # list all files in Network_traffic
    while True:

        files = os.listdir("Network_traffic")

        if files: # check if the new file exists
            captured_traffic = prepar_network_traffic(files[0])
            ML(captured_traffic)
            os.remove(f"Network_traffic\\{files[0]}")
        time.sleep(5)


    



def prepar_network_traffic(file_name):
    
    # static variables
    live_traffic_labels = ["Source IP","Destination IP","Source Port","Destination Port","src_mac","dst_mac","Protocol","Timestamp","Flow Duration","Flow Bytes/s","Flow Packets/s","Fwd Packets/s","Bwd Packets/s","Total Fwd Packets","Total Backward Packets","Total Length of Fwd Packets","Total Length of Bwd Packets","Fwd Packet Length Max","Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std","Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std","Max Packet Length","Min Packet Length","Packet Length Mean","Packet Length Std","Packet Length Variance","Fwd Header Length","Bwd Header Length","min_seg_size_forward","act_data_pkt_fwd","Flow IAT Mean","Flow IAT Max","Flow IAT Min","Flow IAT Std","Fwd IAT Total","Fwd IAT Max","Fwd IAT Min","Fwd IAT Mean","Fwd IAT Std","Bwd IAT Total","Bwd IAT Max","Bwd IAT Min","Bwd IAT Mean","Bwd IAT Std","Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags","FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count","URG Flag Count","ECE Flag Count","Down/Up Ratio","Average Packet Size","Init_Win_bytes_forward","Init_Win_bytes_backward","Active Max","Active Min","Active Mean","Active Std","Idle Max","Idle Min","Idle Mean","Idle Std","Fwd Avg Bytes/Bulk","Fwd Avg Packets/Bulk","Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk","Fwd Avg Bulk Rate","Bwd Avg Bulk Rate","Avg Fwd Segment Size","Avg Bwd Segment Size","CWE Flag Count","Subflow Fwd Packets","Subflow Bwd Packets","Subflow Fwd Bytes","Subflow Bwd Bytes"]

    captured_traffic = pd.read_csv(f"Network_traffic\\{file_name}",names=live_traffic_labels)
    captured_traffic = captured_traffic.round(decimals=2)
    captured_traffic = captured_traffic.fillna(0)

    return captured_traffic

def ML(captured_traffic):

    ML_Bot(captured_traffic)
    ML_SSH(captured_traffic)
    ML_Web(captured_traffic)
    ML_Infiltr(captured_traffic)
    ML_FTP(captured_traffic)
    ML_DOS(captured_traffic)
    ML_PortScan(captured_traffic)


    
main()