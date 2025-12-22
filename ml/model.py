import pandas as pd
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

TRAIN_DATA = "train_data.csv"
TEST_DATA = "test_data.csv"
MODEL_FILE = "rf_model.pkl"

def train_random_forest():
    try:
        train_df = pd.read_csv(TRAIN_DATA)
        test_df = pd.read_csv(TEST_DATA)
    except FileNotFoundError:
        return

   #tach dac trung X va nhan y
    X_train = train_df.drop('label', axis=1)
    y_train = train_df['label']
    
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    print(f"Du lieu train: {X_train.shape}")
    print(f"Du lieu test:  {X_test.shape}")

    # khoi tao train mo hinh  
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)

   #danh gia model
    y_pred = rf_model.predict(X_test)

    print("\nDanh gia mo hinh:")
    print(f"Do chinh xac: {accuracy_score(y_test, y_pred):.4f}")
    print("\nMa tran nham lan:")
    print(confusion_matrix(y_test, y_pred))
    print("\nBao cao phan loai:")
    print(classification_report(y_test, y_pred))
    print("\n--- DAC TRUNG QUAN TRONG ---")
    importances = rf_model.feature_importances_
    feature_names = X_train.columns

    indices = np.argsort(importances)[::-1]

    for i in range(X_train.shape[1]):
        print(f"{i+1}. {feature_names[indices[i]]:<20} : {importances[indices[i]]:.4f}")

    joblib.dump(rf_model, MODEL_FILE)
    print(f"\nModel da duoc luu tai: {MODEL_FILE}")
    print("Done!")

if __name__ == "__main__":
    train_random_forest()