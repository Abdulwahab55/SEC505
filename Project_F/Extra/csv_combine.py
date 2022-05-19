import random
import os
import pandas as pd
import glob


# concatenate all CSVs files togathers of the dataset.


def combine_CSV_FILES():
    all_files = glob.glob("Original_dataset/*.csv")
# concatenate all CSV files 
    dataset = pd.concat(pd.read_csv(f) for f in all_files)
    print(dataset.shape)

    dataset.to_csv("all_data.csv", index=False,encoding="utf-8")

combine_CSV_FILES()