from apig_wsgi import make_lambda_handler
from config.wsgi import application

# Configure this as your entry point in AWS Lambda
lambda_handler = make_lambda_handler(application)
