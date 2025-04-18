from flask import Flask, request, jsonify
from database.cloud_group import database_bp
from google_drive.drive import drive_bp

app = Flask(__name__)

#add blueprints 
app.register_blueprint(database_bp)
app.register_blueprint(drive_bp)

if __name__ == "__main__":
    app.run()