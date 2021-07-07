# -*- coding: utf-8 -*-
"""
Created on Sun Mar  8 10:36:17 2020

@author: created by Sowmya Myneni and updated by Dijiang Huang
"""
import numpy as np
import pandas as pd
from keras.utils import np_utils
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer

def get_processed_data(datasetFile, categoryMappingsPath, classType='binary'):
    inputFile = pd.read_csv(datasetFile, header=None)
    X = inputFile.iloc[:, 0:-2].values
    label_column = inputFile.iloc[:, -2].values
    
    category_1 = np.array(pd.read_csv(categoryMappingsPath + "1.csv", header=None).iloc[:, 0].values)
    category_2 = np.array(pd.read_csv(categoryMappingsPath + "2.csv", header=None).iloc[:, 0].values)
    category_3 = np.array(pd.read_csv(categoryMappingsPath + "3.csv", header=None).iloc[:, 0].values)
    #category_label = np.array(pd.read_csv(categoryMappingsPath + "41.csv", header=None).iloc[:, 0].values)
    ct = ColumnTransformer(
                [('X_one_hot_encoder', OneHotEncoder(categories=[category_1, category_2, category_3], handle_unknown='ignore'), [1,2,3])],    # The column numbers to be transformed ([1, 2, 3] represents three columns to be transferred)
                remainder='passthrough'# Leave the rest of the columns untouched
            )
    X = np.array(ct.fit_transform(X), dtype=np.float)

    from sklearn.preprocessing import StandardScaler
    sc = StandardScaler()
    X = sc.fit_transform(np.array(X))  # Scaling to the range [0,1]
        
    if classType == 'binary':               
        y = []
        for i in range(len(label_column)):
            if label_column[i] == 'normal' or str(label_column[i]) == '0':
                y.append(0)
            else:
                y.append(1)        
        # Convert ist to array
        y = np.array(y)        
    else:    
        #Converting to integers from the mappings file
        label_map = pd.read_csv(categoryMappingsPath + "41.csv", header=None)
        label_category = label_map.iloc[:, 0].values
        label_value = label_map.iloc[:, 1].values
        
        y = []
        for i in range(len(label_column)):
            y.append(label_value[label_category.tolist().index(label_column[i])])
        # Encoding the Dependent Variable
        y = np_utils.to_categorical(y)
    
    return X, y
