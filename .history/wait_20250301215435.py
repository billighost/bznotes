from waitress import serve
from your_flask_app import app  # Import your Flask instance

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=5000)
