import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline
import warnings
warnings.filterwarnings('ignore')

class NetworkSecurityML:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.model_folder = 'models'
        self.dataset_path = 'Dataset/network_security_dataset.csv'
        
        # Create models folder if it doesn't exist
        os.makedirs(self.model_folder, exist_ok=True)
        
    def load_data(self):
        """Load and preprocess the network security dataset"""
        df = pd.read_csv(self.dataset_path)
        
        # Features (excluding target variables)
        feature_cols = ['Packet_Size', 'Transmission_Rate', 'Latency', 'Protocol_Type',
                       'Active_Connections', 'CPU_Usage', 'Memory_Usage', 'Bandwidth_Utilization',
                       'Request_Response_Time', 'Auth_Failures', 'Access_Violations',
                       'Firewall_Blocks', 'IDS_Alerts', 'DWT_Feature_1']
        
        X = df[feature_cols]
        y_anomaly = df['Anomalous_Load']  # Binary classification (0 or 1)
        y_auth_failures = df['Auth_Failures']  # Multi-class classification (0-9 levels)
        
        return X, y_anomaly, y_auth_failures
    
    def train_and_evaluate_models(self, selected_algorithms):
        """Train selected models and return performance metrics"""
        X, y_anomaly, y_auth_failures = self.load_data()
        
        # Split data
        X_train, X_test, y_anomaly_train, y_anomaly_test, y_auth_train, y_auth_test = train_test_split(
            X, y_anomaly, y_auth_failures, test_size=0.2, random_state=42, stratify=y_anomaly
        )
        
        # Apply data balancing using SMOTE for both targets
        smote_anomaly = SMOTE(random_state=42)
        smote_auth = SMOTE(random_state=42)
        
        # Balance anomaly detection data
        X_train_balanced_anomaly, y_anomaly_train_balanced = smote_anomaly.fit_resample(X_train, y_anomaly_train)
        
        # Balance auth failures data
        X_train_balanced_auth, y_auth_train_balanced = smote_auth.fit_resample(X_train, y_auth_train)
        
        print(f"Original anomaly training samples: {len(X_train)}, Balanced: {len(X_train_balanced_anomaly)}")
        print(f"Original auth training samples: {len(X_train)}, Balanced: {len(X_train_balanced_auth)}")
        
        results = {
            'anomaly_classification_results': {},
            'auth_classification_results': {},
            'algorithms_trained': []
        }
        
        for algorithm in selected_algorithms:
            try:
                # Check if model already exists
                anomaly_model_path = os.path.join(self.model_folder, f'{algorithm}_anomaly_classification.pkl')
                auth_model_path = os.path.join(self.model_folder, f'{algorithm}_auth_classification.pkl')
                scaler_path = os.path.join(self.model_folder, f'{algorithm}_scaler.pkl')
                
                if os.path.exists(anomaly_model_path) and os.path.exists(auth_model_path) and os.path.exists(scaler_path):
                    # Load existing models
                    anomaly_model = joblib.load(anomaly_model_path)
                    auth_model = joblib.load(auth_model_path)
                    scaler = joblib.load(scaler_path)
                    
                    # Scale test data
                    X_test_scaled = scaler.transform(X_test)
                    
                    print(f"Loaded existing {algorithm} models")
                else:
                    # Train new models with balanced data
                    anomaly_model, auth_model, scaler = self._train_algorithm(
                        algorithm, X_train_balanced_anomaly, X_train_balanced_auth, X_test, y_anomaly_train_balanced, y_auth_train_balanced
                    )
                    
                    # Save models
                    joblib.dump(anomaly_model, anomaly_model_path)
                    joblib.dump(auth_model, auth_model_path)
                    joblib.dump(scaler, scaler_path)
                    
                    X_test_scaled = scaler.transform(X_test)
                    
                    print(f"Trained and saved {algorithm} models")
                
                # Store models for prediction
                self.models[f'{algorithm}_anomaly_classification'] = anomaly_model
                self.models[f'{algorithm}_auth_classification'] = auth_model
                self.scalers[algorithm] = scaler
                
                # Evaluate models
                anomaly_results = self._evaluate_classification(anomaly_model, X_test_scaled, y_anomaly_test)
                auth_results = self._evaluate_classification(auth_model, X_test_scaled, y_auth_test)
                
                results['anomaly_classification_results'][algorithm] = anomaly_results
                results['auth_classification_results'][algorithm] = auth_results
                results['algorithms_trained'].append(algorithm)
                
            except Exception as e:
                print(f"Error training {algorithm}: {str(e)}")
                continue
        
        return results
    
    def _train_algorithm(self, algorithm, X_train_anomaly, X_train_auth, X_test, y_anomaly_train, y_auth_train):
        """Train a specific algorithm for both anomaly and auth failure classification"""
        # Scale features for both datasets
        scaler_anomaly = StandardScaler()
        scaler_auth = StandardScaler()
        X_train_anomaly_scaled = scaler_anomaly.fit_transform(X_train_anomaly)
        X_train_auth_scaled = scaler_auth.fit_transform(X_train_auth)
        
        if algorithm == 'KNN':
            anomaly_model = KNeighborsClassifier(n_neighbors=5)
            auth_model = KNeighborsClassifier(n_neighbors=5)
        elif algorithm == 'SVC':
            anomaly_model = SVC(kernel='rbf', C=0.01, gamma=10, max_iter=100, random_state=42)
            auth_model = SVC(kernel='rbf', C=0.01, gamma=10, max_iter=100, random_state=42)
        elif algorithm == 'NaiveBayes':
            anomaly_model = GaussianNB()
            auth_model = GaussianNB()
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        # Train models
        anomaly_model.fit(X_train_anomaly_scaled, y_anomaly_train)
        auth_model.fit(X_train_auth_scaled, y_auth_train)
        
        # Use the anomaly scaler as the main scaler (for prediction compatibility)
        return anomaly_model, auth_model, scaler_anomaly
    
    def _evaluate_classification(self, model, X_test, y_test):
        """Evaluate classification model"""
        y_pred = model.predict(X_test)
        
        return {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred, average='weighted', zero_division='warn')),
            'recall': float(recall_score(y_test, y_pred, average='weighted', zero_division='warn')),
            'f1_score': float(f1_score(y_test, y_pred, average='weighted', zero_division='warn'))
        }
    
    
    def predict_single(self, features, algorithm):
        """Make prediction for a single input"""
        try:
            # Load model if not already loaded
            if f'{algorithm}_anomaly_classification' not in self.models:
                self._load_models(algorithm)
            
            # Prepare features
            feature_values = list(features.values())
            X = np.array(feature_values).reshape(1, -1)
            
            # Scale features
            X_scaled = self.scalers[algorithm].transform(X)
            
            # Make predictions
            anomaly_pred = self.models[f'{algorithm}_anomaly_classification'].predict(X_scaled)[0]
            auth_pred = self.models[f'{algorithm}_auth_classification'].predict(X_scaled)[0]
            
            # Get probabilities if available
            try:
                anomaly_proba = self.models[f'{algorithm}_anomaly_classification'].predict_proba(X_scaled)[0]
                anomaly_confidence = float(max(anomaly_proba))
            except:
                anomaly_confidence = 0.0
                
            try:
                auth_proba = self.models[f'{algorithm}_auth_classification'].predict_proba(X_scaled)[0]
                auth_confidence = float(max(auth_proba))
            except:
                auth_confidence = 0.0
            
            return {
                'anomaly_classification_result': {
                    'prediction': int(anomaly_pred),
                    'label': 'Anomalous' if anomaly_pred == 1 else 'Normal',
                    'confidence': anomaly_confidence
                },
                'auth_classification_result': {
                    'prediction': int(auth_pred),
                    'auth_failures_level': int(auth_pred),
                    'confidence': auth_confidence
                }
            }
        except Exception as e:
            raise Exception(f"Prediction error: {str(e)}")
    
    def predict_batch(self, df, algorithm):
        """Make predictions for batch CSV data"""
        try:
            # Load model if not already loaded
            if f'{algorithm}_anomaly_classification' not in self.models:
                self._load_models(algorithm)
            
            # Prepare features (exclude target columns if present)
            feature_cols = ['Packet_Size', 'Transmission_Rate', 'Latency', 'Protocol_Type',
                           'Active_Connections', 'CPU_Usage', 'Memory_Usage', 'Bandwidth_Utilization',
                           'Request_Response_Time', 'Auth_Failures', 'Access_Violations',
                           'Firewall_Blocks', 'IDS_Alerts', 'DWT_Feature_1']
            
            # Check if all required columns are present
            missing_cols = [col for col in feature_cols if col not in df.columns]
            if missing_cols:
                raise Exception(f"Missing required columns: {missing_cols}")
            
            X = df[feature_cols]
            
            # Scale features
            X_scaled = self.scalers[algorithm].transform(X)
            
            # Make predictions
            anomaly_pred = self.models[f'{algorithm}_anomaly_classification'].predict(X_scaled)
            auth_pred = self.models[f'{algorithm}_auth_classification'].predict(X_scaled)
            
            # Prepare results
            results = []
            for i in range(len(X)):
                results.append({
                    'row': i + 1,
                    'anomaly_classification': {
                        'prediction': int(anomaly_pred[i]),
                        'label': 'Anomalous' if anomaly_pred[i] == 1 else 'Normal'
                    },
                    'auth_classification': {
                        'prediction': int(auth_pred[i]),
                        'auth_failures_level': int(auth_pred[i])
                    }
                })
            
            return {
                'total_predictions': len(results),
                'anomalous_count': int(sum(anomaly_pred)),
                'normal_count': int(len(anomaly_pred) - sum(anomaly_pred)),
                'predictions': results[:100]  # Limit to first 100 for display
            }
        except Exception as e:
            raise Exception(f"Batch prediction error: {str(e)}")
    
    def _load_models(self, algorithm):
        """Load saved models for a specific algorithm"""
        try:
            anomaly_model_path = os.path.join(self.model_folder, f'{algorithm}_anomaly_classification.pkl')
            auth_model_path = os.path.join(self.model_folder, f'{algorithm}_auth_classification.pkl')
            scaler_path = os.path.join(self.model_folder, f'{algorithm}_scaler.pkl')
            
            if not all([os.path.exists(path) for path in [anomaly_model_path, auth_model_path, scaler_path]]):
                raise Exception(f"Models for {algorithm} not found. Please train the model first.")
            
            self.models[f'{algorithm}_anomaly_classification'] = joblib.load(anomaly_model_path)
            self.models[f'{algorithm}_auth_classification'] = joblib.load(auth_model_path)
            self.scalers[algorithm] = joblib.load(scaler_path)
            
        except Exception as e:
            raise Exception(f"Error loading {algorithm} models: {str(e)}")
