import psycopg2
from flask import Flask, Blueprint, request, jsonify
import encryption

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
               public_key TEXT
                );""")

cursor.execute("""CREATE TABLE IF NOT EXISTS users (
               id SERIAL PRIMARY KEY,
               first_name VARCHAR(255),
               last_name VARCHAR(255),
               public_key TEXT,
               group_id INT,
               CONSTRAINT group_num FOREIGN KEY(group_id) REFERENCES cloudGroups(group_id)
               );""")


# Function to add a group
@database_bp.route("/add-group", methods = ['POST'])
def add_group():
    cursor = conn.cursor()
    data = request.json
    group_name = data['group_name']

    # Generate key pair for group
    public_key = encryption.generateKeyPair("group_private")

    cursor.execute("INSERT INTO cloudGroups (group_name, public_key) VALUES (%s, %s) RETURNING group_id", (group_name,public_key))
    group_id = cursor.fetchone()[0]  # Retrieve the newly inserted group_id
    conn.commit()
    cursor.close()
    return jsonify({"group_id":group_id}), 200

# Function to add a user
@database_bp.route("/add-user", methods = ['POST'])
def add_user():
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
    
    # Generate key pair
    public_key = encryption.generateKeyPair("user_private")


    # Insert user with auto-increment ID
    cursor.execute("INSERT INTO users (first_name, last_name, public_key, group_id) VALUES (%s, %s, %s, %s) RETURNING id",
                   (first_name, last_name, public_key, group_id))
    user_id = cursor.fetchone()[0]  # Retrieve the new user ID
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
    cursor.execute("SELECT id FROM users WHERE first_name = %s AND last_name = %s", (f_name, l_name))
    result = cursor.fetchone()
    if result: 
        #remove from db 
        cursor.execute("DELETE FROM users WHERE id = %s", result)
        conn.commit()
        cursor.close()
        return jsonify({"message":"User successfully deleted"}), 200
    else:
        cursor.close()
        return jsonify({"message": "ERROR: No user found"}), 400 
    

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
    
def retrieve_group_PK(group_name):
    cursor = conn.cursor()
    # Retrieve group_id
    cursor.execute("SELECT public_key FROM cloudGroups WHERE group_name = %s", (group_name, ))
    result = cursor.fetchone()

    if result:
        group_pk = result[0]
        return group_pk
    else:
        print("Error: Group not found.")
        return False
