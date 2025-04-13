import base64
from flask import Flask, request, jsonify, Blueprint
from googleapiclient import discovery
from httplib2 import Http
from oauth2client import file, client, tools
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
import io
from database.cloud_group import is_in_group, group_exists, retrieve_group_key, retrieve_encrypted_aes, retrieve_iv
from encryption import encrypt_file, decrypt_file
import json
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
    first_name = data['fname']
    last_name = data['lname']
    group_name = data['group_name']
    
    try:
        #Check group exists
        print("Checking group exists...")
        if not group_exists(group_name):
            return jsonify({"message":"ERROR: Group does not exist"}), 400
        #Check user is in group 
        print("Checking in user group...")
        if not is_in_group(first_name, last_name, group_name):
            return jsonify({"message":"ERROR: user not in group"}), 400

        #Encrypt file 
        print("Encrypting file...")
        #Retrieve group's aes key 
        key, iv = retrieve_group_key(group_name)

        db_file_id = encrypt_file(file_contents, "encrypted.txt", group_name, key, iv) 
        print(db_file_id)
        print("Successfully encrypted file")

        #Open encrypted file 
        with open("encrypted.txt", "rb")  as f:
            encrypted_contents = f.read()

        # metadata
        file_metadata = {"name": file_name}

        file_stream = io.BytesIO(encrypted_contents)
        media = MediaIoBaseUpload(file_stream, mimetype="application/octet-stream")
        file = (
            DRIVE.files()
            .create(body=file_metadata, media_body=media, fields="id")
            .execute()
        )
        return jsonify({
            "message": "Successfully uploaded file",
            "drive_file_id": file['id'],
            "db_file_id": db_file_id
        }), 200
    except Exception as e:
        return jsonify({"message": f"ERROR: Cannot upload file : {e}"}), 400
    
#download a file from drive 
@drive_bp.route('/download-file', methods = ['POST'])
def download_file():
    data = request.json
    name = data['file_name']
    file_id = data['file_id']
    db_file_id = data['db_file_id']
    first_name = data['fname']
    last_name = data['lname']
    user_id = data['user_id']
    group_name = data['group_name']

    #retrieve file from drive
    try:
        download_request = DRIVE.files().get_media(fileId=file_id)
        file = io.BytesIO()
        downloader = MediaIoBaseDownload(file,download_request)
        complete = False
        while complete is False:
            status, complete = downloader.next_chunk()
            print(f"Download {int(status.progress() * 100)}.")
        file_contents = file.getvalue()

        #check group exists
        if not group_exists(group_name):
            return jsonify({"message":"ERROR: group does not exist"}), 400
        
        #check user is in group 
        if not is_in_group(first_name, last_name, group_name):
            return jsonify({"message":"User not in group", "Encrypted file": file_contents.decode('latin-1')}), 200

        print("Decrypting file...")
        iv = retrieve_iv(group_name)
        decrypt_file(file_contents, "decrypted.txt", db_file_id, user_id, iv)

        with open("decrypted.txt", "r") as f:
            contents = f.read()

        return jsonify({"message":"file_decrypted", "contents":contents}), 200
    except Exception as e:
        return jsonify({"message": f"ERROR: Cannot download file : {e}"}), 400