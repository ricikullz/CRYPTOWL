
#? CRYPTOWL is a simple web application for sending and reading encrypted messages

import base64
import logging
import secrets
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, render_template, redirect, url_for, flash
from pymysql import connect


app = Flask(__name__)
app.config.from_pyfile('app_config_prod.py')

##################################################
### DB Init, DB table creation, INSERT, SELECT ###
##################################################
# <--- DB Init and first DB table creation
def init_db():
    mysql = connect(
    host = app.config['MYSQL_HOST'],
    user = app.config['MYSQL_USER'],
    password= app.config['MYSQL_PASSWORD'],
    db = app.config['MYSQL_DB']
    )

    cur = mysql.cursor()
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS cryptowl (
            message_id INT AUTO_INCREMENT PRIMARY KEY,
            message_enc_content BLOB NOT NULL,
            message_address TEXT NOT NULL,
            key_hash VARCHAR(200) NOT NULL,
            is_opened BOOLEAN NOT NULL,
            created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP
            )
        '''
    )

    mysql.commit()
    cur.close()
    mysql.close()
# --->

# <--- INSERT data to DB table
def insert_to_db_table(message_enc_content, message_address, key_hash, is_opened):
    mysql = connect(
    host = app.config['MYSQL_HOST'],
    user = app.config['MYSQL_USER'],
    password= app.config['MYSQL_PASSWORD'],
    db = app.config['MYSQL_DB']
    )

    cur = mysql.cursor()
    query = '''INSERT INTO cryptowl (message_enc_content, message_address, key_hash, is_opened) VALUES (%s, %s, %s, %s)'''
    cur.execute(query, (message_enc_content, message_address, key_hash, is_opened))

    mysql.commit()
    cur.close()
    mysql.close()
# --->

# <--- SELECT data from DB table
def select_from_db_table(message_address, key_hash):
    mysql = connect(
    host = app.config['MYSQL_HOST'],
    user = app.config['MYSQL_USER'],
    password= app.config['MYSQL_PASSWORD'],
    db = app.config['MYSQL_DB']
    )

    cur = mysql.cursor()
    query = '''SELECT message_enc_content FROM cryptowl WHERE message_address = %s AND key_hash = %s'''
    cur.execute(query, (message_address, key_hash))
    
    data = cur.fetchone()[0]

    query_update_is_opened = '''UPDATE cryptowl SET is_opened = True WHERE message_address = %s AND key_hash = %s'''
    cur.execute(query_update_is_opened, (message_address, key_hash))

    mysql.commit()
    cur.close()
    mysql.close()

    return data
# --->

# <--- Check if data exists in DB table
def check_select_from_db_table(message_address, key_hash):
    mysql = connect(
    host = app.config['MYSQL_HOST'],
    user = app.config['MYSQL_USER'],
    password= app.config['MYSQL_PASSWORD'],
    db = app.config['MYSQL_DB']
    )

    cur = mysql.cursor()
    query = '''SELECT message_enc_content FROM cryptowl WHERE message_address = %s AND key_hash = %s'''
    cur.execute(query, (message_address, key_hash))
    
    data = cur.fetchone()

    mysql.commit()
    cur.close()
    mysql.close()

    if type(data) == type(None):

        return False
    
    else:

        return True
# --->


init_db()
### --->


##############################################
### CRYPTOGRAPHIC LAYER OF THE APP - BEGIN ###
##############################################
# <--- Hash
def key_hash_generate(key):
    hash_object = SHA512.new(data=key.encode())
    return hash_object.hexdigest()
# --->

# <--- Address
def address_generate():
    return secrets.token_urlsafe(32)
# --->

# <--- Encrypt
def message_encrypt(message, key):
    key_encoded = str(key).encode()
    cipher = AES.new(key=key_encoded, mode=AES.MODE_CBC)
    iv = cipher.iv
    message_encoded = str(message).encode()
    # Pad the message to make its length a multiple of block_size (16 bytes)
    message_padded = pad(message_encoded, AES.block_size)
    encrypted_data = cipher.encrypt(message_padded)
    # Combine IV and ciphertext
    encrypted_bundle = iv + encrypted_data
    # Encode in Base64
    message_encrypted = base64.b64encode(encrypted_bundle)

    return message_encrypted
# --->

# <--- Decrypt
def message_decrypt(message_encrypted, key):
    key_encoded = str(key).encode()
    # Decode Base64 and split IV and ciphertext
    encrypted_bundle = base64.b64decode(message_encrypted)
    iv = encrypted_bundle[:AES.block_size]
    encrypted_data = encrypted_bundle[AES.block_size:]
    
    cipher = AES.new(key=key_encoded, mode=AES.MODE_CBC, iv=iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    # Remove padding
    message_decoded_bytes = unpad(decrypted_data, AES.block_size)
    # Decode bytes to string
    message_decrypted = message_decoded_bytes.decode("utf-8", "ignore")
    
    return message_decrypted
# --->
### --->


##########################
### Main App functions ###
##########################
# <--- Index
@app.route('/')
def index():
    return render_template("index.html")
# --->

# <--- Send Result
@app.route('/send_result.html/<addr_value>/<key_value>', methods=['GET'])
def send_result(addr_value, key_value):
    flash("Message SEND!", category="info")

    return render_template("send_result.html", addr_value=addr_value, key_value=key_value)
# --->
    
# <--- Send message
@app.route('/send.html', methods=['GET','POST'])
def send_message():
    msg_content = ""
    msg_enc_content = ""
    addr_value = ""
    key_value = ""
    key_hash_value = ""

    if request.method == "POST":
        msg_content = request.form['send_msg_textarea']

        if not msg_content:
            flash("Message is EMPTY! Please, enter the message", category="error")

            return render_template("send.html")
        
        else:
            addr_value = address_generate()
            symbols = 'abcdefjhijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+|~`[];:'
            key_value = ''.join(secrets.choice(symbols) for i in range(16))
            key_hash_value = key_hash_generate(key=key_value)
            msg_enc_content = message_encrypt(msg_content, key=key_value)

            # <--- Write data to DB table
            try:
                insert_to_db_table(message_enc_content=msg_enc_content, message_address=addr_value, key_hash=key_hash_value, is_opened=False)

            except Exception as e:
                logging.exception(repr(e))
            # --->
    
            return redirect(url_for("send_result", addr_value=addr_value, key_value=key_value))
    
    return render_template("send.html")
# --->

# <--- Read result
@app.route('/read_result.html/<msg_content>', methods=['GET'])
def read_result(msg_content):
    flash("Message OPENED!", category="info")

    return render_template("read_result.html", msg_content=msg_content)
# --->

# <--- Read message
@app.route('/read.html', methods=['GET','POST'])
def read_message():
    addr_value = ""
    key_value = ""
    msg_content = ""
    msg_enc_content = ""

    if request.method == 'POST':
        addr_value = request.form['read_addr_input']
        key_value = request.form['read_key_input']

        if (not addr_value) or (not key_value):
            flash("Addresss or/and Key ARE EMPTY! Please, enter the Address/Key values", category="error")

            return render_template("read.html")
        
        elif check_select_from_db_table(addr_value, key_hash_generate(key=key_value)) == False:
            flash("Invalid Address or/and Key or Message was deleted!", category="error")

            return render_template("read.html")
        
        else:
            key_hash_value = key_hash_generate(key=key_value)

            # <--- Extract data frrom DB table
            try:
                msg_enc_content = select_from_db_table(addr_value, key_hash_value)
                msg_content = message_decrypt(msg_enc_content, key_value)

            except Exception as e:
                logging.exception(repr(e))
            # --->

            return redirect(url_for("read_result", msg_content=msg_content))
    
    return render_template("read.html")
# --->

if __name__ == '__main__':
    app.run()
### --->