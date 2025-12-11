import serverless_wsgi
from main import app  # Import app từ main.py (app = Flask(__name__))

# Handler cho Vercel serverless
def handler(event, context):
    return serverless_wsgi.handle_request(app, event, context)