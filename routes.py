import os
import json
import pandas as pd
import numpy as np
from flask import render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename
import io
import base64
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from app import app
from ml_utils import NetworkSecurityML

# Initialize ML utility
ml_utils = NetworkSecurityML()

@app.route('/')
def home():
    """Home page with project overview"""
    return render_template('home.html')

@app.route('/eda')
def eda():
    """EDA page with data analysis and visualizations"""
    try:
        # Load the dataset
        df = pd.read_csv('Dataset/network_security_dataset.csv')
        
        # Basic statistics
        stats = {
            'total_samples': len(df),
            'total_features': len(df.columns),
            'anomalous_samples': int(df['Anomalous_Load'].sum()),
            'normal_samples': int(len(df) - df['Anomalous_Load'].sum())
        }
        
        # Generate visualizations
        plots = generate_eda_plots(df)
        
        return render_template('eda.html', stats=stats, plots=plots)
    except Exception as e:
        app.logger.error(f"Error in EDA: {str(e)}")
        flash(f'Error loading data: {str(e)}', 'error')
        return render_template('eda.html', stats=None, plots=None)

@app.route('/performance')
def performance():
    """Classifiers performance comparison page"""
    return render_template('performance.html')

@app.route('/train_models', methods=['POST'])
def train_models():
    """Train selected models and return performance metrics"""
    try:
        selected_algorithms = request.json.get('algorithms', [])
        
        if not selected_algorithms:
            return jsonify({'error': 'No algorithms selected'}), 400
        
        # Train models and get performance metrics
        results = ml_utils.train_and_evaluate_models(selected_algorithms)
        
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Error training models: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/prediction')
def prediction():
    """Prediction page for single input and batch processing"""
    return render_template('prediction.html')

@app.route('/predict_single', methods=['POST'])
def predict_single():
    """Handle single input prediction"""
    try:
        # Get form data
        features = {}
        feature_names = ['Packet_Size', 'Transmission_Rate', 'Latency', 'Protocol_Type', 
                        'Active_Connections', 'CPU_Usage', 'Memory_Usage', 'Bandwidth_Utilization',
                        'Request_Response_Time', 'Auth_Failures', 'Access_Violations', 
                        'Firewall_Blocks', 'IDS_Alerts', 'DWT_Feature_1']
        
        for feature in feature_names:
            features[feature] = float(request.form.get(feature, 0))
        
        selected_algorithm = request.form.get('algorithm')
        
        # Make prediction
        prediction_results = ml_utils.predict_single(features, selected_algorithm)
        
        return jsonify(prediction_results)
    except Exception as e:
        app.logger.error(f"Error in single prediction: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/predict_batch', methods=['POST'])
def predict_batch():
    """Handle batch CSV file prediction"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and file.filename.endswith('.csv'):
            selected_algorithm = request.form.get('algorithm')
            
            # Read CSV file
            df = pd.read_csv(file)
            
            # Make batch predictions
            prediction_results = ml_utils.predict_batch(df, selected_algorithm)
            
            return jsonify(prediction_results)
        else:
            return jsonify({'error': 'Invalid file format. Please upload a CSV file.'}), 400
    except Exception as e:
        app.logger.error(f"Error in batch prediction: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_eda_plots(df):
    """Generate EDA plots and return as base64 encoded images"""
    plots = {}
    
    # Set style
    plt.style.use('default')
    sns.set_palette("husl")
    
    # 1. Distribution of Anomalous Load
    plt.figure(figsize=(8, 6))
    anomaly_counts = df['Anomalous_Load'].value_counts()
    plt.pie(anomaly_counts.values, labels=['Normal', 'Anomalous'], autopct='%1.1f%%', 
            colors=['#28a745', '#dc3545'])
    plt.title('Distribution of Anomalous Load')
    plots['anomaly_distribution'] = get_plot_as_base64()
    
    # 2. Auth Failures Distribution
    plt.figure(figsize=(10, 6))
    auth_counts = df['Auth_Failures'].value_counts().sort_index()
    plt.bar(auth_counts.index, auth_counts.values, color='#007bff')
    plt.xlabel('Auth Failures Count')
    plt.ylabel('Frequency')
    plt.title('Distribution of Authentication Failures')
    plt.xticks(auth_counts.index)
    plots['auth_failures_distribution'] = get_plot_as_base64()
    
    # 3. Correlation Heatmap
    plt.figure(figsize=(12, 10))
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    correlation_matrix = df[numeric_cols].corr()
    sns.heatmap(correlation_matrix, annot=False, cmap='coolwarm', center=0)
    plt.title('Feature Correlation Heatmap')
    plt.tight_layout()
    plots['correlation_heatmap'] = get_plot_as_base64()
    
    # 4. CPU Usage vs Memory Usage scatter plot
    plt.figure(figsize=(10, 6))
    colors = ['red' if x == 1 else 'blue' for x in df['Anomalous_Load']]
    plt.scatter(df['CPU_Usage'], df['Memory_Usage'], c=colors, alpha=0.6)
    plt.xlabel('CPU Usage')
    plt.ylabel('Memory Usage')
    plt.title('CPU Usage vs Memory Usage (Red: Anomalous, Blue: Normal)')
    plt.legend(['Normal', 'Anomalous'])
    plots['cpu_memory_scatter'] = get_plot_as_base64()
    
    # 5. Feature distributions
    plt.figure(figsize=(15, 10))
    important_features = ['Packet_Size', 'Transmission_Rate', 'Latency', 'CPU_Usage']
    for i, feature in enumerate(important_features, 1):
        plt.subplot(2, 2, i)
        plt.hist(df[feature], bins=30, alpha=0.7, color='#007bff')
        plt.xlabel(feature)
        plt.ylabel('Frequency')
        plt.title(f'Distribution of {feature}')
    plt.tight_layout()
    plots['feature_distributions'] = get_plot_as_base64()
    
    return plots

def get_plot_as_base64():
    """Convert current matplotlib plot to base64 string"""
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight', facecolor='white')
    img.seek(0)
    plot_data = base64.b64encode(img.getvalue()).decode()
    plt.close()
    return plot_data
