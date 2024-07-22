#importing required libraries
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn import metrics 
import warnings
warnings.filterwarnings('ignore')
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import plotly.graph_objects as go

def train():
    # Loading data into dataframe
    data = pd.read_csv("phishing.csv")
    data = data.drop(['Index'],axis = 1)
    X = data.drop(["class"],axis =1)
    y = data["class"]
    
    # Splitting the dataset into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 42)
    
    # Random Forest Classifier Model
    forest = RandomForestClassifier(n_estimators=10) 
    forest.fit(X_train,y_train)
    
    # Predictions
    y_train_forest = forest.predict(X_train)
    y_test_forest = forest.predict(X_test)
    
    # Evaluation Metrics
    acc_train_forest = metrics.accuracy_score(y_train,y_train_forest)
    acc_test_forest = metrics.accuracy_score(y_test,y_test_forest)
    f1_score_train_forest = metrics.f1_score(y_train,y_train_forest)
    f1_score_test_forest = metrics.f1_score(y_test,y_test_forest)
    recall_score_train_forest = metrics.recall_score(y_train,y_train_forest)
    recall_score_test_forest = metrics.recall_score(y_test,y_test_forest)
    
    # Printing the evaluation metrics
    print("Random Forest : Accuracy on training Data: {:.3f}".format(acc_train_forest))
    print("Random Forest : Accuracy on test Data: {:.3f}".format(acc_test_forest))
    print("Random Forest : f1_score on training Data: {:.3f}".format(f1_score_train_forest))
    print("Random Forest : f1_score on test Data: {:.3f}".format(f1_score_test_forest))
    print("Random Forest : Recall on training Data: {:.3f}".format(recall_score_train_forest))
    print("Random Forest : Recall on test Data: {:.3f}".format(recall_score_test_forest))
    
    # Saving the trained model
    pickle.dump(forest, open('models/modelr.pkl', 'wb'))
    
    # Confusion Matrix
    confusion_matrix = metrics.confusion_matrix(y_test, y_test_forest)
    
    # Saving the confusion matrix plot using Plotly
    fig = go.Figure(data=go.Heatmap(z=confusion_matrix,
                                     x=['Predicted Negative', 'Predicted Positive'],
                                     y=['Actual Negative', 'Actual Positive'],
                                     colorscale='Viridis'))
    fig.update_layout(title='Confusion Matrix',
                      xaxis_title='Predicted label',
                      yaxis_title='True label')
    fig.write_image("confusion_matrix.png")
    
    # Writing evaluation metrics to results.csv
    results = pd.DataFrame({'Metric': ['Accuracy', 'F1 Score', 'Recall'],
                            'Training': [acc_train_forest, f1_score_train_forest, recall_score_train_forest],
                            'Test': [acc_test_forest, f1_score_test_forest, recall_score_test_forest]})
    return results


