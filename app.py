from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64  # Import the base64 module

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database connection
db = mysql.connector.connect(
    host="localhost",
    user="root",  # Default user for XAMPP
    password="",  # Default password is blank
    database="CodeCrypt"  # Your database name
)
cursor = db.cursor()

@app.route('/')
def index():
    return render_template('index.html')

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        user = cursor.fetchone()

        if user:
            flash('Username or Email already exists', 'danger')
            return redirect(url_for('register'))

        cursor.execute("INSERT INTO users (email, name, username, password) VALUES (%s, %s, %s, %s)",
                       (email, name, username, hashed_password))
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
            stored_hashed_password = user[2]
            if check_password_hash(stored_hashed_password, password):
                session['username'] = user[1]
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
    if 'username' not in session:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('homepage.html', username=session['username'])

# Atbash Cipher
def atbash_cipher(text):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    reversed_alphabet = 'ZYXWVUTSRQPONMLKJIHGFEDCBA'
    result = ''

    for char in text.upper():
        if char in alphabet:
            index = alphabet.index(char)
            converted_char = reversed_alphabet[index]
            result += converted_char
        else:
            result += char  
    return result

@app.route('/atbash', methods=['GET', 'POST'])
def atbash():
    result = ""
    if request.method == 'POST':
        text = request.form['input_text']
        result = atbash_cipher(text)
    return render_template('atbash.html', result=result)

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
    if request.method == 'POST':
        mode = request.form.get('mode')
        shift = int(request.form.get('shift', 3))
        input_text = request.form.get('input_text', '')

        if mode == 'toCipher':
            result = caesar_encrypt(input_text, shift)
        elif mode == 'toText':
            result = caesar_decrypt(input_text, shift)

    return render_template('caesar.html', result=result)

# Binary Encoding and Decoding
@app.route('/binary', methods=['GET', 'POST'])
def binary_code():
    result = ""
    if request.method == 'POST':
        mode = request.form.get('mode')
        input_text = request.form.get('input_text', '')
        if mode == 'toBinary':
            result = ' '.join(format(ord(char), '08b') for char in input_text)
        elif mode == 'toText':
            try:
                result = ''.join(chr(int(binary, 2)) for binary in input_text.split())
            except ValueError:
                result = "Invalid binary input. Please ensure it's 8-bit binary sequences separated by spaces."

    return render_template('binary.html', result=result)

# Affine Cipher
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

@app.route('/affine', methods=['GET', 'POST'])
def affine_cipher():
    result = ""
    if request.method == 'POST':
        mode = request.form.get('mode')
        input_text = request.form.get('input_text', '')
        a_value = int(request.form.get('a_value', '1'))  
        b_value = int(request.form.get('b_value', '0'))  

        a_value = a_value % 26

        # Check if a_value is coprime to 26
        if a_value not in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            result = "The 'a' value must be an odd number that is coprime to 26."
        else:
            try:
                if mode == 'encrypt':
                    result = affine_encrypt(input_text, a_value, b_value)
                elif mode == 'decrypt':
                    result = affine_decrypt(input_text, a_value, b_value)
            except ValueError as e:
                result = str(e) 

    return render_template('affine.html', result=result)


# Base64 Encoding and Decoding
@app.route('/base64', methods=['GET', 'POST'])
def base64_encode_decode():
    result = ""
    if request.method == 'POST':
        mode = request.form.get('mode')
        input_text = request.form.get('input_text', '')

        if mode == 'toBase64':
            result = base64.b64encode(input_text.encode()).decode()
        elif mode == 'toText':
            try:
                result = base64.b64decode(input_text).decode()
            except Exception:
                result = "Invalid Base64 input."

    return render_template('base64.html', result=result)

# Hexadecimal Encoding
@app.route('/hexadecimal', methods=['GET', 'POST'])
def hexadecimal():
    result = ""
    if request.method == 'POST':
        mode = request.form.get('mode')
        input_text = request.form.get('input_text', '')

        if mode == 'toHex':
            result = ''.join(format(ord(char), '02x') for char in input_text).upper()
        elif mode == 'toText':
            try:
                result = ''.join(chr(int(input_text[i:i + 2], 16)) for i in range(0, len(input_text), 2))
            except ValueError:
                result = "Invalid hexadecimal input."

    return render_template('hexadecimal.html', result=result)


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
    # Check if the input contains only valid Morse code characters (., - and space)
    if any(char not in ['.', '-', ' '] for char in morse_code):
        return "Invalid input. Please enter correct Morse Code."
    
    decoded_message = []
    for code in morse_code.split(' '):
        if code in morse_code_dict_reversed:
            decoded_message.append(morse_code_dict_reversed[code])
        else:
            return "Invalid input. Please enter Morse Code."
    return ''.join(decoded_message)

@app.route('/morse', methods=['GET', 'POST'])
def morse():
    result = ''
    if request.method == 'POST':
        mode = request.form.get('mode')
        input_text = request.form.get('input_text', '')

        if mode == 'encode':
            result = encode_to_morse(input_text)
        elif mode == 'decode':
            result = decode_from_morse(input_text)

    return render_template('morse.html', result=result)



# Railfence Cipher
@app.route('/railfence', methods=['GET', 'POST'])
def railfence():
    result = ""
    if request.method == 'POST':
        text = request.form.get('input_text', '').strip().replace(" ", "").lower()  # Normalize input text
        num_rails = request.form.get('num_rails', type=int)
        mode = request.form.get('mode')  # Get mode (encrypt/decrypt)

        if text and num_rails:
            if mode == 'encrypt':
                result = railfence_encrypt(text, num_rails).upper()  # Encrypt and output in uppercase
            elif mode == 'decrypt':
                result = railfence_decrypt(text, num_rails).upper()  # Decrypt and output in uppercase

    return render_template('railfence.html', result=result)

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

# Vigenère Cipher
@app.route('/rot13', methods=['GET', 'POST'])
def rot13():
    result = ""
    if request.method == 'POST':
        text = request.form['input_text']
        result = rot13_cipher(text)
    return render_template('rot13.html', result=result)

def vigenere_cipher(text, keyword, mode="encode"):
    result = []
    keyword_repeated = (keyword * (len(text) // len(keyword) + 1))[:len(text)]
    
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(keyword_repeated[i].upper()) - ord('A')
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
    if request.method == 'POST':
        mode = request.form.get('mode', 'encode')
        text = request.form.get('input_text', '')
        keyword = request.form.get('keyword', '').upper()
        
        if keyword and text:
            result = vigenere_cipher(text, keyword, mode)
            
    return render_template('vigenere.html', result=result)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)