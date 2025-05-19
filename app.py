from flask import Flask, render_template, request, session        # Import Flask components for web app, form handling, and session management
from crypto_logic import generate_keys_encrypt, decrypt_ct2_to_ct1, decrypt_ct1_to_pt  # Import custom crypto functions
import base64                                                     # Import base64 module (convert binary to readable text)ussing ascii 

app = Flask(__name__)                                             # Create a Flask application instance
app.secret_key = "super_secure_demo_key"                         #Set a secret key for secure sessions .
                                                                 # It ensures that the data stored in the session object cannot be tampered with by the client (browser).
                                                                #Without it, Flask will not allow the use of sessions,
                                                                #which your project uses to store intermediate values (like ct2, private_key, etc.) across requests.

@app.route('/', methods=['GET', 'POST'])                          # Define (url path)route for homepage supporting GET(page load) and POST(data processed)
def index():                                                      # Define the main view function
    result = {}                                                   # Initialize an empty dictionary to store results for rendering

    if request.method == 'POST':                                  # Handle form submission
        action = request.form.get('action')                       # Determine which action was triggered (encrypt or decrypt)

        if action == "encrypt":                                   # If user clicked "Encrypt"
            plain_text = request.form.get("plain_text")           # Get the plaintext input from the form
            result = generate_keys_encrypt(plain_text)            # Call encryption function, returns dict with keys, ct1, ct2, etc.
            session["ct2"] = result["ct2"]                         # Store ct2 (RSA-encrypted AES ciphertext) in session
            session["public_key"] = result["public_key"]          # Store generated RSA public key in session
            session["private_key"] = result["private_key"]        # Store generated RSA private key in session
            session["nonce"] = result["nonce"]                    # Store AES nonce in session for decryption(EAX)
            session["tag"] = result["tag"]                        # Store AES authentication tag in session
                                                                  #a nonce: a random number used once (like a salt),
                                                                  #a tag: an authentication code used to verify the integrity of the ciphertext.

        elif action == "ct2_decrypt":                              # If user clicked "Decrypt CT2"
            ct2 = request.form.get("ct2")                          # Get ct2 (RSA encrypted ct1) from the form
            private_key = request.form.get("private_key")          # Get RSA private key from the form
            result = decrypt_ct2_to_ct1(ct2, private_key)          # Decrypt ct2 to get ct1 and AES key

            if "ct1" in result:                                    # If decryption successful and ct1 present
                session["ct1"] = result["ct1"]                     # Store ct1 (AES ciphertext) in session
                session["aes_key_recovered"] = result["aes_key_recovered"]  # Store recovered AES key

        elif action == "ct1_decrypt":                              # If user clicked "Decrypt CT1"
            ct1 = request.form.get("ct1")                          # Get AES ciphertext from form
            aes_key = request.form.get("aes_key")                  # Get AES key from form
            nonce = session.get("nonce")                           # Retrieve nonce from session
            tag = session.get("tag")                               # Retrieve authentication tag from session
            result = decrypt_ct1_to_pt(ct1, aes_key, nonce, tag)   # Decrypt ct1 using AES to get plaintext

    return render_template("index.html", result=result)            # Render result on index.html template

if __name__ == '__main__':                                         # Check if this script is the main program
    app.run(debug=True, port=5003)                                 # Run the app in debug mode on port 5003
