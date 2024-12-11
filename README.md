
# CodeCrypt
![CodeCrypt Logo](README-images/logo.png)

CodeCrypt is a web application that provides secure encryption and decryption of text using various classical cipher methods, as well as data representation. Designed for cryptography enthusiasts, it features user authentication for managing encrypted data and an intuitive interface for hands-on experience with encryption techniques.

## Table of Contents
- [Features](#features)
- [Ciphers and Encoding Tools](#ciphers-and-encoding-tools)
- [System Architecture](#system-architecture)
- [Applied Computer Science Concept](#applied-computer-science-concept)
- [Algorithms Used](#algorithms-used)
- [Security Mechanisms](#security-mechanisms)
- [Development Process and Design Decisions](#development-process-and-design-decisions)
- [Correctness and Efficiency](#correctness-and-efficiency)
- [Installation/How to Run the Project](#installation)
- [Usage](#usage)
- [File Structure](#file-structure)
- [Contributors](#contributors)
- [Acknowledgement](#Acknowledgement)

---

## Features

### User Authentication
- Secure registration and login system using hashed passwords.
- Session-based authentication for personalized user experience.
- **Forgot Password**: Allows users to recover their account by resetting their password via email.

### Cryptography Tools
- Encode and decode text using classical or traditional ciphers and encoding schemes.
- Fun-to-use, friendly interface suitable for both practical applications and casual exploration of cryptography.

### User-Friendly Interface
- Intuitive design with a consistent layout for all cipher pages.
- Sidebars and headers for easy navigation.

### Favorites and History
- **Favorites**: Allow users to mark frequently used ciphers and tools as favorites for quick access.
- **History**: Track the user's recent encryption and decryption activities for easy reference and re-use. Includes options for **filtering** and **sorting** by:
  - Cipher type
  - Recent or oldest activity

### Profile Editing
- Users can manage and update their profile details, such as username, name, and password, ensuring a personalized experience.

### Dark Mode
- A dark mode feature for users who prefer a darker interface, reducing eye strain and providing a more comfortable viewing experience in low-light environments.

### Responsive Design
- Accessible across devices with mobile-friendly layouts.

---

## Ciphers and Encoding Tools
CodeCrypt supports the following tools:  
1. **Affine Cipher**  
2. **Atbash Cipher**  
3. **Base64 Encoding**  
4. **Binary Encoding**  
5. **Caesar Cipher**  
6. **Hexadecimal Encoding**  
7. **Morse Code**  
8. **Rail Fence Cipher**  
9. **ROT13 Cipher**  
10. **Vigenère Cipher**

![CodeCrypt Homepage](README-images/homepage.png)

Each cipher tool includes:  
- Input fields for plain text or encoded text.  
- Options to toggle between encryption and decryption.  
- Detailed results/conversion displayed in real-time.  

---

## Installation
### Prerequisites
- [Python 3.x](https://www.python.org/)
- [Flask](https://flask.palletsprojects.com/)
- [MySQL Database](https://www.mysql.com/)
- [XAMPP](https://www.apachefriends.org/) (for MySQL setup)

### Steps
1. **Clone the Repository**  
   ```bash
   git clone https://github.com/lizaloraine/CodeCrypt.git
   cd CodeCrypt

2. **Set Up MySQL Database**
   - Create a database named CodeCrypt.
   - Use the SQL queries provided in the [schema.sql](schema.sql) file to set up the database tables.

3. **Install Dependencies**
   ```bash
   pip install flask flask-mysqldb werkzeug
   pip install Flask-Mail

4. **Run the Application**
   ```bash
   python app.py
- The application will be accessible at http://127.0.0.1:5000.

---

## Usage

### 1. Registration and Login
- **Register** with your name, email, username, and password.
- **Log in** to access the cipher tools.

### 2. Select a Cipher Tool
- Navigate through the **sidebar** or use the **card containers** on the homepage to select a cipher or encoding tool.
- Input the text that you want to **encrypt** or **decrypt** as needed.

### 3. Results
- The **results** of the encryption or decryption process will be displayed in a dedicated area beside the input field.

### 4. Favorites
- You can **mark** your frequently used ciphers as **favorites** for easy access later.
- These **favorites** will be displayed in a separate section for quick selection.

### 5. History
- The app keeps a **history** of your past operations.
- You can **view** and **filter** your history by **cipher type** or sort it by **newest** or **oldest** to revisit previous encryptions or decryptions.

### 6. Logout
- You can securely **log out** from the application when you're finished using it.

---

## File Structure

The directory structure of the CodeCrypt web application is as follows:
![CodeCrypt Directory Structure](README-images/structure.png)

### Explanation:
- **`static/`**: Contains static files like CSS, images, and JavaScript.
  - Contains the stylesheets for the app, such as `loginregister.css`, `homepage.css`, and so on.
  - **`images/`**: This folder holds any image assets for the web app.
  - **`js/`**: Contains JavaScript file like `header.js` for any interactive components.
- **`templates/`**: Contains the HTML templates for the pages.
  - Files like `login.html`, `register.html`, `homepage.html`, etc., which are used for rendering different parts of the web app.
- **`app.py`**: The main Python script for running the Flask application and handling routes.

---

## Technologies Used

- **Backend**: Python (Flask)
- **Frontend**: HTML, CSS, JavaScript
- **Database**: MySQL
- **Password Hashing**: Werkzeug
- **Email Handling**: Flask-Mail
- **Session Management**: Flask
- **Serialization**: ItsDangerous

---

## Contributors

- **Project Author**: trioBytes Team
  - Ignacio, Liza Loraine M. as the *Project Manager/Fullstack Developer*
  - Balbuena, Jeff Lawrence C. as the *Frontend Developer*
  - Godoy, Hillarie R. as the *Backend Developer*

- **Special Thanks**:
  - to Ms. Fatima Marie Agdon, our instructor.

- **Project Context**:
  - This web application project was developed as the **final project** for the **IT 314 - Web Systems and Technologies** course.

---
