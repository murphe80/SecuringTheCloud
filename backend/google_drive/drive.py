from flask import Flask, request, jsonify, Blueprint
from googleapiclient import discovery
from httplib2 import Http
from oauth2client import file, client, tools
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
import io

# Make blueprint
drive_bp = Blueprint("drive_bp", __name__) 

SCOPES = 'https://www.googleapis.com/auth/drive'
store = file.Storage('storage.json')
creds = store.get()
if not creds or creds.invalid:
    flow = client.flow_from_clientsecrets('credentials.json', SCOPES)
    creds = tools.run_flow(flow, store)

DRIVE = discovery.build('drive', 'v3', http=creds.authorize(Http()))

# Upload file endpoint
@drive_bp.route('/upload-file', methods=['POST'])
def upload_file():
    data = request.json
    if 'file_name' not in data or 'contents' not in data:
        return jsonify({"message": "Missing required fields"}), 400
    
    file_name = data['file_name']
    file_contents = data['contents']
    
    try:
        file_metadata = {"name": file_name}
        file_stream = io.BytesIO(file_contents.encode('utf-8'))

        #TODO: encrypt file 

        media = MediaIoBaseUpload(file_stream, mimetype="application/octet-stream")
        file = (
            DRIVE.files()
            .create(body=file_metadata, media_body=media, fields="id")
            .execute()
        )
        return jsonify({
            "message": "Successfully uploaded file",
            "file_id": file['id']
        }), 200
    except Exception as e:
        return jsonify({"message": f"ERROR: Cannot upload file : {e}"}), 400
    
#download a file from drive 
@drive_bp.route('/download-file', methods = ['POST'])
def download_file():
    data = request.json
    name = data['file_name']
    file_id = data['file_id']
    #retrieve file from drive
    try:
        download_request = DRIVE.files().get_media(fileId=file_id)
        file = io.BytesIO()
        downloader = MediaIoBaseDownload(file,download_request)
        complete = False
        while complete is False:
            status, complete = downloader.next_chunk()
            print(f"Download {int(status.progress() * 100)}.")
            
        #TODO: decrypt file 

        return file.getvalue()
    except Exception as e:
        return jsonify({"message": f"ERROR: Cannot download file : {e}"}), 400