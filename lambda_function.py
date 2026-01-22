import os
from apig_wsgi import make_lambda_handler
from config.wsgi import application

# Set Django settings module for Lambda (must be set before importing Django)
# Use production settings directly for Lambda deployment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.production")


# Configure this as your entry point in AWS Lambda
lambda_handler = make_lambda_handler(application)
