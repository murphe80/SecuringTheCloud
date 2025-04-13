import os
import psycopg2
from flask import Flask, Blueprint, request, jsonify
from cryptography import x509

#create blueprint 
database_bp = Blueprint("database_bp", __name__)

conn = psycopg2.connect(database="postgres",
                        host="localhost",
                        user="postgres",
                        password="Chopin2022!",
                        port="5432")



cursor = conn.cursor()

#initialise tables 
cursor.execute("""CREATE TABLE IF NOT EXISTS cloudGroups(
               group_id SERIAL PRIMARY KEY,
               group_name VARCHAR(255),
               aes_key BYTEA,
               iv BYTEA
                );""")

cursor.execute("""CREATE TABLE IF NOT EXISTS users (
               id SERIAL PRIMARY KEY,
               first_name VARCHAR(255),
               last_name VARCHAR(255),
               group_id INT,
               cert TEXT,
               CONSTRAINT group_num FOREIGN KEY(group_id) REFERENCES cloudGroups(group_id)
               );""")

cursor.execute("""CREATE TABLE IF NOT EXISTS file_keys(
               file_key_id SERIAL PRIMARY KEY, 
               file_id TEXT, 
               user_id INT, 
               encrypted_aes_key BYTEA, 
               CONSTRAINT users FOREIGN KEY(user_id) REFERENCES users(id)
               );""")


# Function to add a group
@database_bp.route("/add-group", methods = ['POST'])
def add_group():
    cursor = conn.cursor()
    data = request.json
    group_name = data['group_name']

    # generate AES key and iv for group 
    key = os.urandom(32)
    iv = os.urandom(16)

    cursor.execute("INSERT INTO cloudGroups (group_name, aes_key, iv) VALUES (%s, %s, %s) RETURNING group_id", (group_name,key, iv))
    group_id = cursor.fetchone()[0]  # Retrieve the newly inserted group_id
    conn.commit()
    cursor.close()
    return jsonify({"group_id":group_id}), 200

# Function to add a user
@database_bp.route("/add-user", methods = ['POST'])
def add_user():
    import encryption

    cursor = conn.cursor()
    data = request.json
    first_name = data['first_name']
    last_name = data['last_name']
    group_name = data['group_name']


    # Retrieve group_id
    cursor.execute("SELECT group_id FROM cloudGroups WHERE group_name = %s", (group_name,))
    result = cursor.fetchone()

    if result:
        group_id = result[0]
    else:
        print("Error: Group not found.")
        return jsonify({"message":"False"}), 400
    
    # Insert user with auto-increment ID
    cursor.execute("INSERT INTO users (first_name, last_name, cert, group_id) VALUES (%s, %s, %s, %s) RETURNING id",
                   (first_name, last_name, "", group_id))
    user_id = cursor.fetchone()[0]  # Retrieve the new user ID
    
    # Generate pem encoded cert 
    cert = encryption.generate_key_and_csr(user_id)

    # Update cert 
    cursor.execute("UPDATE users SET cert = %s WHERE id = %s", (cert, str(user_id)))

    conn.commit()
    cursor.close()
    return jsonify({"user_id":user_id}), 200

#remove user from group 
@database_bp.route('/remove-user', methods = ['POST'])
def remove_user():
    cursor = conn.cursor()
    data = request.json
    f_name = data['fname']
    l_name = data['lname']
    # retrieve user id 
    cursor.execute("SELECT id, group_id FROM users WHERE first_name = %s AND last_name = %s", (f_name, l_name))
    result = cursor.fetchall()

    
    if result: 
        user_id = result[0][0]
        group_id = result[0][1]
        print(user_id)
        #remove file keys from db
        cursor.execute("DELETE FROM file_keys WHERE user_id = %s", (user_id, ))
        #remove from db 
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id, ))

        #regenerate key for group 
        update_key(cursor,group_id)
        conn.commit()
        cursor.close()
        return jsonify({"message":"User successfully deleted"}), 200
    else:
        cursor.close()
        return jsonify({"message": "ERROR: No user found"}), 400 
    
def update_key(cursor, group_id):
    key = os.urandom(32)
    iv = os.urandom(16)
    cursor.execute("UPDATE cloudGroups SET aes_key=%s, iv=%s WHERE group_id = %s", (key, iv, group_id))
    print("Updated aes key for cloud group")
    return 

#remove group from database 
@database_bp.route('/remove-group', methods = ['POST'])
def remove_group():
    cursor = conn.cursor()
    data = request.json
    g_name = data['name']
    cursor.execute("SELECT group_id FROM cloudGroups WHERE group_name = %s", (g_name, ))
    result = cursor.fetchone()

    if result: 
        #remove from db 
        cursor.execute("DELETE FROM cloudGroups WHERE group_id = %s", result)
        conn.commit()
        cursor.close()
        return jsonify({"message":"Group successfully deleted"}), 200
    else:
        cursor.close()
        return jsonify({"message": "ERROR: No group found"}), 400

#function to check if user in a group
def is_in_group(first_name, last_name, group_name):
    cursor = conn.cursor()
    # Retrieve group_id
    cursor.execute("SELECT group_id FROM cloudGroups WHERE group_name = %s", (group_name, ))
    result = cursor.fetchone()

    if result:
        group_id = result[0]
    else:
        print("Error: Group not found.")
        return False

    cursor.execute("SELECT * FROM users WHERE first_name = %s AND last_name = %s AND group_id = %s", (first_name, last_name, group_id))
    in_group = cursor.fetchone() is not None
    cursor.close()
    return in_group

def group_exists(group_name):
    cursor = conn.cursor()
    cursor.execute("SELECT group_id FROM cloudGroups WHERE group_name = %s", (group_name, ))
    result = cursor.fetchone()
    cursor.close()
    if result:
        return True
    else:
        return False
    
def retrieve_group_key(group_name):
    cursor = conn.cursor()
    # Retrieve group_id
    cursor.execute("SELECT aes_key, iv FROM cloudGroups WHERE group_name = %s", (group_name, ))
    result = cursor.fetchone()

    if result:   
        cursor.close()
        aes_key, iv = result
        return aes_key, iv
    
    else:
        cursor.close()
        print("Error: Group not found.")
        return False
    
@database_bp.route('/retrieve_group_members', methods = ['GET'])
def retrieve_group_members(group_name):
    data = request.json
    group_name = data['group_name']
    cursor = conn.cursor()
    cursor.execute("SELECT group_id FROM cloudGroups WHERE group_name = %s", (group_name, ))
    result = cursor.fetchone()
    if result:
        group_id = result[0] 
        cursor.execute("SELECT id, first_name, last_name FROM users WHERE group_id = %s", (group_id, ))
        users = cursor.fetchall()  # Use fetchall() to get all users
        if users:
            cursor.close()
            # Convert list of tuples to list of user IDs
            return users
        else:
            cursor.close()
            print("No users found in group")
            return []
    else:
        cursor.close()
        print("Error: Group not found")
        return []



def retrieve_public_key(user_id):
    """Gets public key of user"""
    cursor = conn.cursor()

    cursor.execute("SELECT cert FROM users WHERE id = %s", (user_id, ))
    cert_pem = cursor.fetchone()
    if cert_pem: 
        cursor.close()
        cert = x509.load_pem_x509_certificate(cert_pem[0].encode())
        print("Retrieved cert")
    
        # Extract the public key
        public_key = cert.public_key()
        return public_key
    else:
        cursor.close()
        print("No key found in users")



def add_encrypted_aes_keys(key, user_id, file_id):
    """Inserts encrypted aes key for a user into file_keys table"""
    cursor = conn.cursor()
    # Ensure key is in proper format for database
    # if isinstance(key, bytes):
    #     # Convert bytes to psycopg2 Binary object
    #     from psycopg2.binary import Binary
    #     key = Binary(key)

    cursor.execute("INSERT INTO file_keys(file_id, user_id, encrypted_aes_key) VALUES(%s, %s, %s)", (file_id, user_id, key))
    print("Inserted aes key to file_keys")
    conn.commit()
    cursor.close()

def retrieve_encrypted_aes(user_id, file_id):
    cursor = conn.cursor()

    cursor.execute("SELECT encrypted_aes_key FROM file_keys WHERE user_id = %s and file_id = %s", (user_id, file_id))
    key = cursor.fetchone()

    if key:
        cursor.close()
        return key[0]
    else:
        cursor.close()
        print("Error retrieving encrypted key")
        return 

def retrieve_iv(group_name):
    cursor = conn.cursor()

    cursor.execute("SELECT iv FROM cloudGroups WHERE group_name = %s", (group_name, ))
    result = cursor.fetchone()
    cursor.close()
    if result:
        return result[0]
    else:
        print("Unable to retrieve IV")