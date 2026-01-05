import os
import logging
from flask import Flask

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "network_security_ml_app_secret_key")

# Configure upload folders
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MODEL_FOLDER'] = 'models'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create directories if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['MODEL_FOLDER'], exist_ok=True)

# Import routes
from routes import *

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
