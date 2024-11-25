from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64
from flask_mail import Mail, Message
from io import BytesIO
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import random
import string



app = Flask(__name__)
app.secret_key = os.urandom(24)
s = URLSafeTimedSerializer(app.secret_key) 

db = mysql.connector.connect(
    host="localhost",
    user="root",  
    password="",  
    database="CodeCrypt" 
)
cursor = db.cursor()

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465  # SSL
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'codecrypt.batstateu@gmail.com' 
app.config['MAIL_PASSWORD'] = 'awyd cegu ifft eloj' 
app.config['MAIL_DEFAULT_SENDER'] = 'codecrypt.batstateu@gmail.com'  

mail = Mail(app)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        email_exists = cursor.fetchone()

        if email_exists:
            flash('Email already registered. Enter a new one.', 'danger')
            return redirect(url_for('register'))

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        username_exists = cursor.fetchone()

        if username_exists:
            flash('Username already taken. Enter a new one.', 'danger')
            return redirect(url_for('register'))

        cursor.execute("SELECT user_id FROM users ORDER BY user_id DESC LIMIT 1")
        last_user = cursor.fetchone()

        if last_user:
            last_user_id = last_user[0]
            user_number = int(last_user_id.replace("CCUSER", "")) + 1
            new_user_id = f"CCUSER{user_number:04d}"
        else:
            new_user_id = "CCUSER0001"

        cursor.execute("INSERT INTO users (user_id, email, name, username, password) VALUES (%s, %s, %s, %s, %s)",
                       (new_user_id, email, name, username, hashed_password))
        db.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')



def send_reset_email(user_email, reset_token, username):
    reset_url = url_for('reset_password', token=reset_token, _external=True)

 
    msg = Message('Reset Your Password', recipients=[user_email])

    
    html_body = f"""
    <html>
        <body>
            <div style="text-align: center; font-family: Arial, sans-serif;">
                <h1 style="color: blue;">CodeCrypt</h1>
                <p><strong>Encrypt It, Decrypt It,<br>Keep It Safe with CodeCrypt</strong></p>
                <p>Hey, {username}</p>
                <p>Your CodeCrypt password can be reset by clicking the link below. If you did not request a new password, please ignore this email.</p>
                <p><a href="{reset_url}" style="text-decoration: none; font-size: 16px; font-weight: bold; color: #007BFF;">Click this to reset your password</a></p>
            </div>
        </body>
    </html>
    """

    
    msg.html = html_body

  
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")



@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		identifier = request.form['identifier']
		password = request.form['password']

		cursor.execute("SELECT * FROM users WHERE email = %s OR username = %s", (identifier, identifier))
		user = cursor.fetchone()

		if user:
			stored_hashed_password = user[4]
			if check_password_hash(stored_hashed_password, password):
				session['user_id'] = user[0]  
				session['username'] = user[3]  
                
				return redirect(url_for('homepage'))
			else:
				flash('Invalid email/username or password', 'danger')
		else:
			flash('Invalid email/username or password', 'danger')

	return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

       
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            token = s.dumps(email, salt='password-reset')

            cursor.execute("UPDATE users SET reset_token = %s WHERE email = %s", (token, email))
            db.commit()

           
            reset_url = url_for('reset_password', token=token, _external=True)

            html_body = f"""
            <html>
                <body>
                    <div style="text-align: center; font-family: Arial, sans-serif;">
                        <h1 style="color: blue;">CodeCrypt</h1>
                        <p><strong>Encrypt It, Decrypt It,<br>Keep It Safe with CodeCrypt</strong></p>
                        <p>Hey, {user[3]}</p>
                        <p>Your CodeCrypt password can be reset by clicking the link below. If you did not request a new password, please ignore this email.</p>
                        <p><a href="{reset_url}" style="text-decoration: none; font-size: 16px; font-weight: bold; color: #007BFF;">Click this to reset your password</a></p>
                    </div>
                </body>
            </html>
            """

            msg = Message('Reset Your Password', recipients=[email])
            msg.html = html_body  

            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'success')
            except Exception as e:
                flash(f'Error sending email: {str(e)}', 'danger')
                return redirect(url_for('login'))

            return redirect(url_for('login'))
        else:
            flash('No account found with that email.', 'danger')

    return render_template('login.html')



@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        flash('The reset link is expired.', 'danger')
        return redirect(url_for('login'))
    except Exception as e:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = generate_password_hash(new_password)

        
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        db.commit()

        cursor.execute("UPDATE users SET reset_token = NULL WHERE email = %s", (email,))
        db.commit()

        flash('Your password has been reset successfully.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/homepage')
def homepage():
    if 'user_id' not in session:
        return redirect(url_for('login')) 

    user_id = session['user_id']
    username = session['username']
    

    cursor.execute(
    "SELECT email FROM users WHERE user_id = %s", (user_id,)
    )
    result = cursor.fetchone()

    if result:  
        email = result[0]  
    else:
        email = 'Error fetching.'  

    
    cursor.execute(
    "SELECT name FROM users WHERE user_id = %s", (user_id,)
    )
    result_name = cursor.fetchone()

    if result_name:  
        name = result_name[0]  
    else:
        name = 'Error fetching.' 
    
   
    cursor.execute(
        "SELECT crypt_id FROM favorites WHERE user_id = %s", (user_id,)
    )
    favorites = cursor.fetchall()

    
    favorite_ciphers = {favorite[0] for favorite in favorites}
    print("Favorite Ciphers:", favorite_ciphers)
    
    return render_template('homepage.html', username=username, email=email, name=name, user_id=user_id, favorite_ciphers=favorite_ciphers)
 
 
@app.route("/changepassword", methods=["POST"])
def change_password():
    if request.method == "POST":
        user_id = session.get("user_id") 

        current_password = request.form["currentPassword"]
        new_password = request.form["newPassword"]
        confirm_password = request.form["confirmPassword"]

        cursor.execute("SELECT password FROM users WHERE user_id = %s", (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            hashed_password = user_data[0]  

            if not check_password_hash(hashed_password, current_password):
                flash("Current password is incorrect.", "error")
                return redirect(url_for("homepage")) 

            if current_password == new_password:
                flash("Current password and new password cannot be the same.", "error")
                return redirect(url_for("homepage"))

            if new_password != confirm_password:
                flash("New password and confirmation do not match.", "error")
                return redirect(url_for("homepage"))
            
            hashed_new_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = %s WHERE user_id = %s", (hashed_new_password, user_id))
            db.commit()
            flash("Password changed successfully!", "success")
            return redirect(url_for("homepage")) 

        flash("User not found.", "error")
        return redirect(url_for("homepage")) 

    return redirect(url_for("homepage"))


@app.route('/changename', methods=['POST'])
def change_name():
    if request.method == "POST":
        if 'user_id' not in session:
            return redirect(url_for('login'))  

        user_id = session['user_id']
        new_name = request.form['newName']

        
        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            current_name = user_data[0] 

            if current_name == new_name:
                flash("Current name and new name cannot be the same.", "error")
                return redirect(url_for("homepage"))


            cursor.execute("UPDATE users SET name = %s WHERE user_id = %s", (new_name, user_id))
            db.commit()
            flash("Name changed successfully!", "success")
            return redirect(url_for("homepage"))  

        flash("User not found.", "error")
        return redirect(url_for("homepage"))  

    
    return redirect(url_for('homepage'))


@app.route('/changeusername', methods=['POST'])
def change_username():
    if request.method == "POST": 
        if 'user_id' not in session:
            return redirect(url_for('login'))  

        user_id = session['user_id']
        current_username = session.get('username')
        new_username = request.form.get('newUsername')

        if current_username:
            
            if current_username == new_username:
                flash("Current username and new username cannot be the same.", "error")
                return redirect(url_for("homepage"))

            
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (new_username,))
            result = cursor.fetchone()
            if result and result[0] > 0:
                flash("Username already exists. Enter another one.", "error")
                return redirect(url_for("homepage"))

            
            cursor.execute("UPDATE users SET username = %s WHERE user_id = %s", (new_username, user_id))
            db.commit()
            
            session['username'] = new_username
            flash("Username updated successfully!", "success")
            return redirect(url_for("homepage"))

        flash("User not found.", "error")
        return redirect(url_for("homepage"))

    return redirect(url_for('homepage'))


def atbash_cipher(text):
    alphabet_upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    reversed_alphabet_upper = 'ZYXWVUTSRQPONMLKJIHGFEDCBA'
    alphabet_lower = 'abcdefghijklmnopqrstuvwxyz'
    reversed_alphabet_lower = 'zyxwvutsrqponmlkjihgfedcba'
    result = ''

    for char in text:
        if char in alphabet_upper:
            index = alphabet_upper.index(char)
            converted_char = reversed_alphabet_upper[index]
            result += converted_char
        elif char in alphabet_lower:
            index = alphabet_lower.index(char)
            converted_char = reversed_alphabet_lower[index]
            result += converted_char
        else:
            result += char
    return result


@app.route('/atbash', methods=['GET', 'POST'])
def atbash():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if request.method == 'POST':
       
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        
       
        mode = request.form.get('mode')
        
       
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('atbash'))  

        
        if mode == 'toCipher':
            mode_id = 'Text to Atbash Cipher'
        elif mode == 'toText':
            mode_id = 'Atbash Cipher to Text'

        text = request.form['input_text']

        result = atbash_cipher(text)

        crypt_id = 'Atbash Cipher' 
     
        insert_history(user_id, crypt_id, mode_id, None, None, None, None, None, text, result)

    return render_template('atbash.html', result=result, email=email, username=username, name=name, user_id=user_id)


def caesar_encrypt(text, shift):
    encrypted = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


@app.route('/caesar', methods=['GET', 'POST'])
def caesar_cipher():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if request.method == 'POST':
         
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        
        mode = request.form.get('mode')

        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('caesar')) 

        shift = int(request.form.get('shift', 3))  
        input_text = request.form.get('input_text', '')

        if mode == 'toCipher':
            mode_id = 'Text to Caesar Cipher'
            result = caesar_encrypt(input_text, shift)
        elif mode == 'toText':
            mode_id = 'Caesar Cipher to Text'
            result = caesar_decrypt(input_text, shift)
            
        crypt_id = 'Caesar Cipher'
        insert_history(user_id, crypt_id, mode_id, None, None, shift, None, None, input_text, result)

    return render_template('caesar.html', result=result, email=email, username=username, name=name, user_id=user_id)


@app.route('/binary', methods=['GET', 'POST'])
def binary_code():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if request.method == 'POST':
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        
        mode = request.form.get('mode')
        input_text = request.form.get('input_text', '')
        crypt_id = 'Binary Encoding' 
        if mode == 'toBinary':
            mode_id = 'Text to Binary'
            result = ' '.join(format(ord(char), '08b') for char in input_text)
        elif mode == 'toText':
            mode_id = 'Binary to Text'
            try:
                result = ''.join(chr(int(binary, 2)) for binary in input_text.split())
            except ValueError:
                result = "Error. Invalid input. Please enter again."

        insert_history(user_id, crypt_id, mode_id, None, None, None, None, None, input_text, result)
  

    return render_template('binary.html', result=result, email=email, username=username, name=name, user_id=user_id)

def affine_encrypt(text, a, b):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted_char = chr(((a * (ord(char) - shift_base) + b) % 26) + shift_base)
            result += encrypted_char
        else:
            result += char 
    return result


def affine_decrypt(text, a, b):
    result = ""
    a_inv = None
    
    for i in range(26):
        if (a * i) % 26 == 1:
            a_inv = i
            break

    if a_inv is None:
        raise ValueError("The 'a' value must be coprime to 26.")

    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
   
            decrypted_char = (a_inv * ((ord(char) - shift_base - b) % 26)) % 26 + shift_base
            result += chr(decrypted_char) 
        else:
            result += char 

    return result


@app.route('/affine', methods=['GET', 'POST'])
def affine_cipher():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if request.method == 'POST':
        if not user_id:
            return redirect(url_for('login'))

        mode = request.form.get('mode')
        input_text = request.form.get('input_text', '')
        a_value = int(request.form.get('a_value', '1'))
        b_value = int(request.form.get('b_value', '0'))

    
        a_value = a_value % 26
        if a_value not in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            result = "The 'a' value must be an odd number that is coprime to 26."
        else:
    
            if b_value < 1:
                b_value = 1 

            try:
              
                if mode == 'encrypt':
                    result = affine_encrypt(input_text, a_value, b_value)
                elif mode == 'decrypt':
                    result = affine_decrypt(input_text, a_value, b_value)

               
                mode_id = 'Text to Affine Cipher' if mode == 'encrypt' else 'Affine Cipher to Text'
                crypt_id = 'Affine Cipher'

             
                insert_history(user_id, crypt_id, mode_id, a_value, b_value, None, None, None, input_text, result)

            except ValueError as e:
                result = str(e)  

    return render_template('affine.html', result=result, email=email, username=username, name=name, user_id=user_id)




@app.route('/base64', methods=['GET', 'POST'])
def base64_encode_decode():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'
    if request.method == 'POST':
      
        user_id = session.get('user_id')
        if not user_id:
      
            return redirect(url_for('login'))
        
        mode = request.form.get('mode')
        
   
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('base64')) 

        input_text = request.form.get('input_text', '')

        
        if mode == 'toBase64':
            mode_id = 'Text to Base64'
            result = base64.b64encode(input_text.encode()).decode()
        elif mode == 'toText':
            mode_id = 'Base64 to Text'
            try:
                result = base64.b64decode(input_text).decode()
            except Exception:
                result = "Error. Invalid input. Please enter again."

        crypt_id = 'Base64 Encoding'  
        insert_history(user_id, crypt_id, mode_id, None, None, None, None, None, input_text, result)

    return render_template('base64.html', result=result, email=email, username=username, name=name, user_id=user_id)



@app.route('/hexadecimal', methods=['GET', 'POST'])
def hexadecimal():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')


        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'
    if request.method == 'POST':
          
        user_id = session.get('user_id')
        if not user_id:
       
            return redirect(url_for('login'))
   
        mode = request.form.get('mode')
        
        
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('hexadecimal')) 
        
        input_text = request.form.get('input_text', '')

        if mode == 'toHex':
            mode_id = 'Text to Hexadecimal'
            result = ''.join(format(ord(char), '02x') for char in input_text).upper()
        elif mode == 'toText':
            mode_id = 'Hexadecimal to Text'
            try:
                result = ''.join(chr(int(input_text[i:i + 2], 16)) for i in range(0, len(input_text), 2))
            except ValueError:
                result = "Error. Invalid input. Please enter again."
        
        crypt_id = 'Hexadecimal Encoding'
        insert_history(user_id, crypt_id, mode_id, None, None, None, None, None, input_text, result)

    return render_template('hexadecimal.html', result=result, email=email, username=username, name=name, user_id=user_id)


morse_code_dict = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', '0': '-----', ' ': '/'
}


morse_code_dict_reversed = {value: key for key, value in morse_code_dict.items()}

def encode_to_morse(text):
    return ' '.join(morse_code_dict.get(char.upper(), '') for char in text)

def decode_from_morse(morse_code):

    morse_code = morse_code.strip()
    
   
    if not morse_code:
        return "Error. Invalid input. Please enter again."
    
   
    if any(char not in ['.', '-', ' '] for char in morse_code):
        return "Error. Invalid input. Please enter again."
    
    decoded_message = []
    for code in morse_code.split(' '):
        if code in morse_code_dict_reversed:
            decoded_message.append(morse_code_dict_reversed[code])
        elif code == '/':
            decoded_message.append(' ')
        else:
            return "Error. Invalid input. Please enter again."
    return ''.join(decoded_message)


@app.route('/morse', methods=['GET', 'POST'])
def morse():
    result = ''
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if request.method == 'POST':
  
        user_id = session.get('user_id')
        if not user_id:
           
            return redirect(url_for('login'))
   
        mode = request.form.get('mode')
        
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('morse'))
        
      
        input_text = request.form.get('input_text', '').strip()

        if mode == 'encode':
            mode_id = 'Text to Morse Code'
            result = encode_to_morse(input_text)
        elif mode == 'decode':
            mode_id = 'Morse Code to Text'
            result = decode_from_morse(input_text)

        crypt_id = 'Morse Code'
        insert_history(user_id, crypt_id, mode_id, None, None, None, None, None, input_text, result)

    return render_template('morse.html', result=result, email=email, username=username, name=name, user_id=user_id)



@app.route('/railfence', methods=['GET', 'POST'])
def railfence():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

   
        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'
    if request.method == 'POST':
         
        user_id = session.get('user_id')
        if not user_id:
           
            return redirect(url_for('login'))
        
        text = request.form.get('input_text', '').strip()
        mode = request.form.get('mode')
       
        if request.form.get('remove_spaces') == 'yes':
            text = text.replace(" ", "")

        
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('railfence'))  
        
        num_rails = int(request.form.get('num_rails', 2))

        if text and num_rails:
            if mode == 'encrypt':
                mode_id = 'Text to Rail Fence Cipher'
                result = railfence_encrypt(text, num_rails)
            elif mode == 'decrypt':
                mode_id = 'Rail Fence Cipher to Text'
                result = railfence_decrypt(text, num_rails)
    
        crypt_id = 'Rail Fence Cipher'
        insert_history(user_id, crypt_id, mode_id, None, None, None, None, num_rails, text, result)

    return render_template('railfence.html', result=result, email=email, username=username, name=name, user_id=user_id)

def railfence_encrypt(text, num_rails):
    rails = ['' for _ in range(num_rails)]
    direction_down = False
    current_rail = 0

    for char in text:
        rails[current_rail] += char
        if current_rail == 0:
            direction_down = True
        elif current_rail == num_rails - 1:
            direction_down = False
        current_rail += 1 if direction_down else -1

    return ''.join(rails)

def railfence_decrypt(text, num_rails):
   
    length = len(text)
    rails = [['' for _ in range(length)] for _ in range(num_rails)]
    idx, direction_down = 0, False

    for i in range(length):
        rails[idx][i] = '*'
        if idx == 0:
            direction_down = True
        elif idx == num_rails - 1:
            direction_down = False
        idx += 1 if direction_down else -1

    idx = 0
    for i in range(num_rails):
        for j in range(length):
            if rails[i][j] == '*' and idx < len(text):
                rails[i][j] = text[idx]
                idx += 1

   
    result = []
    idx, direction_down = 0, False
    for i in range(length):
        result.append(rails[idx][i])
        if idx == 0:
            direction_down = True
        elif idx == num_rails - 1:
            direction_down = False
        idx += 1 if direction_down else -1

    return ''.join(result)




def rot13_cipher(text):
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        elif 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        else:
            result += char  
    return result


@app.route('/rot13', methods=['GET', 'POST'])
def rot13():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

      
        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if request.method == 'POST':
        user_id = session.get('user_id')
        if not user_id:
           
            return redirect(url_for('login'))

        mode = request.form.get('mode')
        
        
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('rot13'))  

        text = request.form.get('input_text', '').strip()

    
        if mode == 'encode':
            mode_id = 'Text to ROT13 Cipher'
            result = rot13_cipher(text)
        elif mode == 'decode':
            mode_id = 'ROT13 Cipher to Text'
            result = rot13_cipher(text)

    
        crypt_id = 'ROT13 Cipher'
        insert_history(user_id, crypt_id, mode_id, None, None, None, None, None, text, result)

    return render_template('rot13.html', result=result, email=email, username=username, name=name, user_id=user_id)



def vigenere_cipher(text, keyword, mode="encode"):
    result = []
    keyword_repeated = ""
    keyword_index = 0

    
    for char in text:
        if char.isalpha():
            keyword_repeated += keyword[keyword_index % len(keyword)].upper()
            keyword_index += 1
        else:
            keyword_repeated += ' '  

 
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(keyword_repeated[i]) - ord('A')
            if mode == "decode":
                shift = -shift
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)

    return ''.join(result)


@app.route('/vigenere', methods=['GET', 'POST'])
def vigenere():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')


        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if request.method == 'POST':
         
        user_id = session.get('user_id')
        if not user_id:
           
            return redirect(url_for('login'))
        
        
        mode = request.form.get('mode')
        
        
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('vigenere'))  
        
       
        keyword = request.form.get('keyword', 'key').upper()
        text = request.form.get('input_text', '')

        if keyword and text:
            if mode == 'encode':
                mode_id = 'Text to Vigenère Cipher'
                result = vigenere_cipher(text, keyword, mode)
            elif mode == 'decode':
                mode_id = 'Vigenère Cipher to Text'
                result = vigenere_cipher(text, keyword, mode)
    
        crypt_id = 'Vigenère Cipher'
        insert_history(user_id, crypt_id, mode_id, None, None, None, keyword, None, text, result)
    return render_template('vigenere.html', result=result, email=email, username=username, name=name, user_id=user_id)




def insert_history(user_id, crypt_id, mode_id, a_value=None, b_value=None, shift=None, key=None, rail=None, input_text="", output_text=""):
    try:
        if output_text == "Error. Invalid input. Please enter again.":
            return  
     
        cursor.execute("SELECT crypt_id FROM ciphers WHERE type_of_tool = %s", (crypt_id,))
        crypt_id = cursor.fetchone()[0]

       
        cursor.execute("SELECT mode_id FROM conversion WHERE type_of_conversion = %s", (mode_id,))
        mode_id = cursor.fetchone()[0]

       
        cursor.execute("SELECT MAX(history_id) FROM history")
        max_history_id = cursor.fetchone()[0]
        if max_history_id:
            last_id_number = int(max_history_id.replace('histo', ''))
            new_history_id = f"histo{last_id_number + 1:05d}"
        else:
            new_history_id = "histo00001"

       
        columns = ["history_id", "user_id", "crypt_id", "mode_id", "input", "output"]
        values = [new_history_id, user_id, crypt_id, mode_id, input_text, output_text]
        
        
        if a_value is not None:
            columns.append("a_value")
            values.append(a_value)
        if b_value is not None:
            columns.append("b_value")
            values.append(b_value)
        if shift is not None:
            columns.append("shift")
            values.append(shift)
        if key is not None:
            columns.append("`key`")  
            values.append(key)
        if rail is not None:
            columns.append("rail")
            values.append(rail)

      
        sql_query = f"INSERT INTO history ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(values))})"
        cursor.execute(sql_query, values)

      
        db.commit()

    except Exception as e:
        print(f"Error inserting history: {e}")
        db.rollback()



@app.route('/allhistory', methods=['GET'])
def all_history():
   
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        
        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if not user_id:
        flash("Please log in to view your history.")
        return redirect(url_for('login'))


    cipher_type = request.args.get('cipher_type', '')
    sort_order = request.args.get('sort_order', 'recent')  

    cipher_filter = ""
    if cipher_type:
        cipher_filter = "AND c.type_of_tool = %s"
    
   
    order_by = "ORDER BY h.date_time DESC" if sort_order == 'recent' else "ORDER BY h.date_time ASC"

    
    query = f'''
    SELECT h.date_time, h.crypt_id, h.mode_id, h.input, h.output, h.shift, h.key, h.a_value, h.b_value, h.rail, c.type_of_tool, co.type_of_conversion
    FROM history h
    JOIN ciphers c ON h.crypt_id = c.crypt_id
    JOIN conversion co ON h.mode_id = co.mode_id
    WHERE h.user_id = %s {cipher_filter}
    {order_by}
    '''
    
   
    params = (user_id,)
    if cipher_type:
        params += (cipher_type,)
    
    cursor.execute(query, params)
    history_records = cursor.fetchall()


    history = []
    for record in history_records:
        conversion_type = record[10]
        mode_name = record[11]

        history_entry = {
            'timestamp': record[0],
            'conversion_type': conversion_type,
            'mode_type': mode_name,
            'input': record[3],
            'output': record[4]
        }

        if record[5] is not None:
            history_entry['shift'] = record[5]
        if record[6] and record[6] != 'n/a':
            history_entry['key'] = record[6]
        if record[7] is not None:
            history_entry['a_value'] = record[7]
        if record[8] is not None:
            history_entry['b_value'] = record[8]
        if record[9] is not None:
            history_entry['rail'] = record[9]

        
        history.append(history_entry)

   
    return render_template('allhistory.html', history=history, email=email, username=username, name=name)




@app.route('/toggle-favorite', methods=['POST'])
def toggle_favorite():
    
     
    user_id = session.get('user_id')  


    if user_id is None:
        return jsonify({"message": "User not logged in."}), 401

   
    data = request.get_json()
    tool_name = data.get('tool_name')
    description = data.get('description')
    icon_text = data.get('icon_text')
    is_favorited = data.get('is_favorited')
    href = data.get('href')

    
    cursor.execute("SELECT crypt_id FROM ciphers WHERE type_of_tool = %s", (tool_name,))
    cipher = cursor.fetchone()

    if cipher:
        crypt_id = cipher[0]

        if is_favorited:
         
            cursor.execute(
                "SELECT * FROM favorites WHERE user_id = %s AND crypt_id = %s",
                (user_id, crypt_id)
            )
            existing_favorite = cursor.fetchone()

            if not existing_favorite:
                
                cursor.execute("SELECT fav_id FROM favorites ORDER BY fav_id DESC LIMIT 1")
                result = cursor.fetchone()
                if result:
                
                    last_id = int(result[0][3:])
                    next_id = last_id + 1
                else:
                   
                    next_id = 1

                fav_id = f"FAV{next_id:04d}"  

        
                cursor.execute("""
                    INSERT INTO favorites (fav_id, user_id, crypt_id, description, icon_text, href)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (fav_id, user_id, crypt_id, description, icon_text, href))
                db.commit()
                return jsonify({"message": f"Added {tool_name} to favorites."})
            else:
                return jsonify({"message": f"{tool_name} is already in favorites."})

        else:
            
            cursor.execute("DELETE FROM favorites WHERE user_id = %s AND crypt_id = %s", (user_id, crypt_id))
            db.commit()
            return jsonify({"message": f"Removed {tool_name} from favorites."})

    return jsonify({"message": "Tool not found."}), 404



@app.route('/favorites')
def favorites():
     
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        
        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if 'user_id' not in session:
        return redirect(url_for('login'))


    
    cursor.execute("""
        SELECT c.type_of_tool, f.description, f.icon_text, f.href
        FROM favorites f
        JOIN ciphers c ON f.crypt_id = c.crypt_id
        WHERE f.user_id = %s
        ORDER BY c.type_of_tool ASC
    """, (user_id,))
    favorites = cursor.fetchall()

    
    if favorites:
        
        return render_template('favorites.html', favorites=favorites, email=email, username=username, name=name)
    else:
       
        flash("You don't have any favorites yet. Add some from the homepage!")
        return render_template('favorites.html', favorites=[], email=email, username=username, name=name)


@app.route('/contacts')
def contacts():
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        email_result = cursor.fetchone()
        if email_result:
            email = email_result[0]
        else:
            email = 'Error fetching.'

        cursor.execute("SELECT name FROM users WHERE user_id = %s", (user_id,))
        name_result = cursor.fetchone()
        if name_result:
            name = name_result[0]
        else:
            name = 'Error fetching.'

    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template('contacts.html', email=email, username=username, name=name)




@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
