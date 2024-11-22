from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64 

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database connection
db = mysql.connector.connect(
    host="localhost",
    user="root",  
    password="",  
    database="CodeCrypt" 
)
cursor = db.cursor()

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
				flash('Login successful!', 'success')
				return redirect(url_for('homepage'))
			else:
				flash('Invalid email/username or password', 'danger')
		else:
			flash('Invalid email/username or password', 'danger')

	return render_template('login.html')


# Homepage Route
@app.route('/homepage')
def homepage():
    # Ensure the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login page if not logged in

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


# CHANGE PASSWORD 
@app.route("/changepassword", methods=["POST"])
def change_password():
    if request.method == "POST":
        user_id = session.get("user_id")  # Assuming user_id is stored in the session

        # Retrieve current password, new password, and confirm password from the form
        current_password = request.form["currentPassword"]
        new_password = request.form["newPassword"]
        confirm_password = request.form["confirmPassword"]

        # Fetch the current hashed password from the database for the logged-in user
        cursor.execute("SELECT password FROM users WHERE user_id = %s", (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            hashed_password = user_data[0]  # Assuming password is stored as hashed

            # Check if the current password is correct
            if not check_password_hash(hashed_password, current_password):
                flash("Current password is incorrect.", "error")
                return redirect(url_for("homepage"))  # Redirect to homepage after flash message

            # Check if current password and new password are the same
            if current_password == new_password:
                flash("Current password and new password cannot be the same.", "error")
                return redirect(url_for("homepage"))

            # Check if new password and confirmation match
            if new_password != confirm_password:
                flash("New password and confirmation do not match.", "error")
                return redirect(url_for("homepage"))

            # Hash the new password and update it in the database
            hashed_new_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = %s WHERE user_id = %s", (hashed_new_password, user_id))
            db.commit()
            flash("Password changed successfully!", "success")
            return redirect(url_for("homepage"))  # Redirect after successful password change

        flash("User not found.", "error")
        return redirect(url_for("homepage"))  # Redirect if user is not found

    return redirect(url_for("homepage"))



@app.route('/changename', methods=['POST'])
def change_name():
    if request.method == "POST":
        if 'user_id' not in session:
            return redirect(url_for('login'))  # Redirect if the user is not logged in

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
            return redirect(url_for('login'))  # Redirect if the user is not logged in

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





# Atbash Cipher
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

        # Fetch email and name from the database
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

    # Handle POST request for encryption/decryption
    if request.method == 'POST':
       
        user_id = session.get('user_id')
        if not user_id:
            # flash("Please log in to perform this action.")
            return redirect(url_for('login'))
        
       
        mode = request.form.get('mode')
        
       
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('atbash'))  

        
        if mode == 'toCipher':
            mode_id = 'Text to Atbash Cipher'
        elif mode == 'toText':
            mode_id = 'Atbash Cipher to Text'

        # Get the input text from the form
        text = request.form['input_text']

        # Call the atbash cipher function to process the text
        result = atbash_cipher(text)

        # Insert the history into the database
        crypt_id = 'Atbash Cipher'  # Atbash cipher identifier
     
        insert_history(user_id, crypt_id, mode_id, None, None, None, None, None, text, result)

    return render_template('atbash.html', result=result, email=email, username=username, name=name, user_id=user_id)


# Caesar Cipher
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

        # Fetch email and name from the database
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
            # flash("Please log in to perform this action.")
            return redirect(url_for('login'))
        
        # Get the mode selected by the user
        mode = request.form.get('mode')
        
        # If no mode is selected, flash an error message and do not process further
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('caesar'))  # Stay on the current page
        
        # Get shift and input text from form
        shift = int(request.form.get('shift', 3))  # Default shift is 3
        input_text = request.form.get('input_text', '')

        # Perform encryption or decryption based on selected mode
        if mode == 'toCipher':
            mode_id = 'Text to Caesar Cipher'
            result = caesar_encrypt(input_text, shift)
        elif mode == 'toText':
            mode_id = 'Caesar Cipher to Text'
            result = caesar_decrypt(input_text, shift)
    
        # Insert the operation into the history
        crypt_id = 'Caesar Cipher'
        insert_history(user_id, crypt_id, mode_id, None, None, shift, None, None, input_text, result)

    return render_template('caesar.html', result=result, email=email, username=username, name=name, user_id=user_id)

# Binary Encoding and Decoding
@app.route('/binary', methods=['GET', 'POST'])
def binary_code():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        # Fetch email and name from the database
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
        # Check if user_id is available in session
        user_id = session.get('user_id')
        if not user_id:
            # flash("Please log in to perform this action.")
            return redirect(url_for('login'))
        
        # Get the mode selected by the user
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

# Affine Cipher Encryption
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

# Affine Cipher Decryption
def affine_decrypt(text, a, b):
    result = ""
    a_inv = None
    
    # Find modular inverse of a
    for i in range(26):
        if (a * i) % 26 == 1:
            a_inv = i
            break

    if a_inv is None:
        raise ValueError("The 'a' value must be coprime to 26.")

    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            # Apply decryption formula to reverse encryption
            decrypted_char = (a_inv * ((ord(char) - shift_base - b) % 26)) % 26 + shift_base
            result += chr(decrypted_char)  # Convert back to character
        else:
            result += char  # Non-alphabetic characters are added unchanged

    return result

# Affine Cipher
@app.route('/affine', methods=['GET', 'POST'])
def affine_cipher():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        # Fetch email and name from the database
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

    # Handle POST request for encryption/decryption
    if request.method == 'POST':
        if not user_id:
            # flash("Please log in to perform this action.")
            return redirect(url_for('login'))

        mode = request.form.get('mode')
        input_text = request.form.get('input_text', '')
        a_value = int(request.form.get('a_value', '1'))
        b_value = int(request.form.get('b_value', '0'))

        # Ensure a_value is within the valid range and coprime to 26
        a_value = a_value % 26
        if a_value not in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            result = "The 'a' value must be an odd number that is coprime to 26."
        else:
            # Ensure b_value is at least 1
            if b_value < 1:
                b_value = 1  # Set to 1 if it's less than 1

            try:
                # Perform encryption or decryption
                if mode == 'encrypt':
                    result = affine_encrypt(input_text, a_value, b_value)
                elif mode == 'decrypt':
                    result = affine_decrypt(input_text, a_value, b_value)

                # Define mode_id based on the operation
                mode_id = 'Text to Affine Cipher' if mode == 'encrypt' else 'Affine Cipher to Text'
                crypt_id = 'Affine Cipher'

                # Insert history into the database
                insert_history(user_id, crypt_id, mode_id, a_value, b_value, None, None, None, input_text, result)

            except ValueError as e:
                result = str(e)  # Handle errors

    # Render the template with all variables
    return render_template('affine.html', result=result, email=email, username=username, name=name, user_id=user_id)




# Base64 Encoding and Decoding
@app.route('/base64', methods=['GET', 'POST'])
def base64_encode_decode():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        # Fetch email and name from the database
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
        # Check if user_id is available in session
        user_id = session.get('user_id')
        if not user_id:
            # flash("Please log in to perform this action.")
            return redirect(url_for('login'))
        
        # Get the mode selected by the user
        mode = request.form.get('mode')
        
        # If no mode is selected, flash an error message and do not process further
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('base64'))  # Stay on the current page

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

# Hexadecimal Encoding
@app.route('/hexadecimal', methods=['GET', 'POST'])
def hexadecimal():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        # Fetch email and name from the database
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
            # flash("Please log in to perform this action.")
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

# Reverse dictionary for decoding
morse_code_dict_reversed = {value: key for key, value in morse_code_dict.items()}

def encode_to_morse(text):
    return ' '.join(morse_code_dict.get(char.upper(), '') for char in text)

def decode_from_morse(morse_code):
    # Remove leading and trailing spaces
    morse_code = morse_code.strip()
    
    # Return an error if the input is empty after trimming
    if not morse_code:
        return "Error. Invalid input. Please enter again."
    
    # Check if the input contains only valid Morse code characters (., -, and space)
    if any(char not in ['.', '-', ' '] for char in morse_code):
        return "Error. Invalid input. Please enter again."
    
    decoded_message = []
    for code in morse_code.split(' '):
        if code in morse_code_dict_reversed:
            decoded_message.append(morse_code_dict_reversed[code])
        elif code == '/':  # Add space for word separation if '/' is used
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

        # Fetch email and name from the database
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
            # flash("Please log in to perform this action.")
            return redirect(url_for('login'))
   
        mode = request.form.get('mode')
        
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('morse'))
        
        # Remove leading and trailing whitespace
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




# Railfence Cipher

@app.route('/railfence', methods=['GET', 'POST'])
def railfence():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        # Fetch email and name from the database
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
            # flash("Please log in to perform this action.")
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
    # Calculate the pattern of the rail
    length = len(text)
    rails = [['' for _ in range(length)] for _ in range(num_rails)]
    idx, direction_down = 0, False

    # Mark positions to place characters
    for i in range(length):
        rails[idx][i] = '*'
        if idx == 0:
            direction_down = True
        elif idx == num_rails - 1:
            direction_down = False
        idx += 1 if direction_down else -1

    # Place characters in marked positions
    idx = 0
    for i in range(num_rails):
        for j in range(length):
            if rails[i][j] == '*' and idx < len(text):
                rails[i][j] = text[idx]
                idx += 1

    # Read the characters in a zigzag pattern
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



# ROT13 Cipher
def rot13_cipher(text):
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        elif 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        else:
            result += char  # Keep non-alphabet characters as is
    return result

# ROT13 Cipher
@app.route('/rot13', methods=['GET', 'POST'])
def rot13():
    result = ""
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        # Fetch email and name from the database
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
            # flash("Please log in to perform this action.")
            return redirect(url_for('login'))

        mode = request.form.get('mode')
        
        # If no mode is selected, flash an error message and do not process further
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('rot13'))  

        text = request.form.get('input_text', '').strip()

        # Determine the mode of operation and process accordingly
        if mode == 'encode':
            mode_id = 'Text to ROT13 Cipher'
            result = rot13_cipher(text)
        elif mode == 'decode':
            mode_id = 'ROT13 Cipher to Text'
            result = rot13_cipher(text)

        # Record the action in the history
        crypt_id = 'ROT13 Cipher'
        insert_history(user_id, crypt_id, mode_id, None, None, None, None, None, text, result)

    return render_template('rot13.html', result=result, email=email, username=username, name=name, user_id=user_id)



def vigenere_cipher(text, keyword, mode="encode"):
    result = []
    keyword_repeated = ""
    keyword_index = 0

    # Build keyword_repeated only for alphabetic characters
    for char in text:
        if char.isalpha():
            keyword_repeated += keyword[keyword_index % len(keyword)].upper()
            keyword_index += 1
        else:
            keyword_repeated += ' '  # Placeholder for non-alphabetic characters

    # Process each character in the text
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

        # Fetch email and name from the database
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
            # flash("Please log in to perform this action.")
            return redirect(url_for('login'))
        
        # Get the mode selected by the user
        mode = request.form.get('mode')
        
        # If no mode is selected, flash an error message and do not process further
        if not mode:
            flash("Please select an option before entering text.")
            return redirect(url_for('vigenere'))  # Stay on the current page
        
        # Get shift and input text from form
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
        # Fetch the crypt_id for Affine Cipher (or any cipher)
        cursor.execute("SELECT crypt_id FROM ciphers WHERE type_of_tool = %s", (crypt_id,))
        crypt_id = cursor.fetchone()[0]

        # Fetch the mode_id for the selected conversion
        cursor.execute("SELECT mode_id FROM conversion WHERE type_of_conversion = %s", (mode_id,))
        mode_id = cursor.fetchone()[0]

        # Generate a unique history_id (e.g., histo00001, histo00002, ...)
        cursor.execute("SELECT MAX(history_id) FROM history")
        max_history_id = cursor.fetchone()[0]
        if max_history_id:
            last_id_number = int(max_history_id.replace('histo', ''))
            new_history_id = f"histo{last_id_number + 1:05d}"
        else:
            new_history_id = "histo00001"

        # Prepare the SQL query dynamically based on available parameters
        columns = ["history_id", "user_id", "crypt_id", "mode_id", "input", "output"]
        values = [new_history_id, user_id, crypt_id, mode_id, input_text, output_text]
        
        # Add optional columns and values
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
            columns.append("`key`")  # Use backticks for reserved keyword 'key'
            values.append(key)
        if rail is not None:
            columns.append("rail")
            values.append(rail)

        # Construct the dynamic insert query
        sql_query = f"INSERT INTO history ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(values))})"
        cursor.execute(sql_query, values)

        # Commit the changes to the database
        db.commit()

    except Exception as e:
        print(f"Error inserting history: {e}")
        db.rollback()



@app.route('/allhistory', methods=['GET'])
def all_history():
    # Check if user_id is available in session
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        # Fetch email and name from the database
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

    # Get filter and sort parameters from the request
    cipher_type = request.args.get('cipher_type', '')
    sort_order = request.args.get('sort_order', 'recent')  # Default to 'recent' if not provided

    # Construct WHERE clause for cipher type filter
    cipher_filter = ""
    if cipher_type:
        cipher_filter = "AND c.type_of_tool = %s"
    
    # Set sorting order based on sort_order input
    order_by = "ORDER BY h.date_time DESC" if sort_order == 'recent' else "ORDER BY h.date_time ASC"

    # SQL query to get the conversion history for the logged-in user, with filtering and sorting
    query = f'''
    SELECT h.date_time, h.crypt_id, h.mode_id, h.input, h.output, h.shift, h.key, h.a_value, h.b_value, h.rail, c.type_of_tool, co.type_of_conversion
    FROM history h
    JOIN ciphers c ON h.crypt_id = c.crypt_id
    JOIN conversion co ON h.mode_id = co.mode_id
    WHERE h.user_id = %s {cipher_filter}
    {order_by}
    '''
    
    # Execute the query with parameters
    params = (user_id,)
    if cipher_type:
        params += (cipher_type,)
    
    cursor.execute(query, params)
    history_records = cursor.fetchall()

    # Process the conversion types for display
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

        # Add the entry to the history list
        history.append(history_entry)

    # Render the history page template with the conversion history
    return render_template('allhistory.html', history=history, email=email, username=username, name=name)




@app.route('/toggle-favorite', methods=['POST'])
def toggle_favorite():
    
     
    user_id = session.get('user_id')  


    if user_id is None:
        return jsonify({"message": "User not logged in."}), 401

    # Get the data from the request
    data = request.get_json()
    tool_name = data.get('tool_name')
    description = data.get('description')
    icon_text = data.get('icon_text')
    is_favorited = data.get('is_favorited')
    href = data.get('href')

    # Query to find the crypt_id of the tool
    cursor.execute("SELECT crypt_id FROM ciphers WHERE type_of_tool = %s", (tool_name,))
    cipher = cursor.fetchone()

    if cipher:
        crypt_id = cipher[0]

        if is_favorited:
            # Check if this favorite already exists
            cursor.execute(
                "SELECT * FROM favorites WHERE user_id = %s AND crypt_id = %s",
                (user_id, crypt_id)
            )
            existing_favorite = cursor.fetchone()

            if not existing_favorite:
                # Generate the next fav_id in the format "FAV0001", "FAV0002", etc.
                cursor.execute("SELECT fav_id FROM favorites ORDER BY fav_id DESC LIMIT 1")
                result = cursor.fetchone()
                if result:
                    # Increment the numeric part of the last fav_id
                    last_id = int(result[0][3:])
                    next_id = last_id + 1
                else:
                    # If no rows exist, start with 1
                    next_id = 1

                fav_id = f"FAV{next_id:04d}"  # Format as "FAV0001", "FAV0002", etc.

                # Insert into favorites if not already present
                cursor.execute("""
                    INSERT INTO favorites (fav_id, user_id, crypt_id, description, icon_text, href)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (fav_id, user_id, crypt_id, description, icon_text, href))
                db.commit()
                return jsonify({"message": f"Added {tool_name} to favorites."})
            else:
                return jsonify({"message": f"{tool_name} is already in favorites."})

        else:
            # Delete from favorites if toggled off
            cursor.execute("DELETE FROM favorites WHERE user_id = %s AND crypt_id = %s", (user_id, crypt_id))
            db.commit()
            return jsonify({"message": f"Removed {tool_name} from favorites."})

    return jsonify({"message": "Tool not found."}), 404





# Route for displaying favorites
@app.route('/favorites')
def favorites():
     
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        # Fetch email and name from the database
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


    # Query to fetch the user's favorite ciphers and related data
    cursor.execute("""
        SELECT c.type_of_tool, f.description, f.icon_text, f.href
        FROM favorites f
        JOIN ciphers c ON f.crypt_id = c.crypt_id
        WHERE f.user_id = %s
        ORDER BY c.type_of_tool ASC
    """, (user_id,))
    favorites = cursor.fetchall()

    
    if favorites:
        # Render the page with the list of favorites if available
        return render_template('favorites.html', favorites=favorites, email=email, username=username, name=name)
    else:
        # Display a message if the user has no favorites
        flash("You don't have any favorites yet. Add some from the homepage!")
        return render_template('favorites.html', favorites=[], email=email, username=username, name=name)




# COntacts
@app.route('/contacts')
def contacts():
    email = None  
    name = None  
    username = None 
    user_id = session.get('user_id')  

    if user_id:
        username = session.get('username', 'Guest')

        # Fetch email and name from the database
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





# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    session.clear()
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)