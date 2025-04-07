import subprocess
from flask import Flask, jsonify, request, render_template, send_from_directory
import os
import shutil

# Initialize the Flask application
app = Flask(__name__)

INTERMEDIATE_CA_CERT = "/Users/filiporlikowski/Documents/SEGPRD/project/pki/intermediate/certs/intermediateCA.crt"
INTERMEDIATE_CA_KEY = "/Users/filiporlikowski/Documents/SEGPRD/project/pki/intermediate/private/intermediateCA.key"
CRL_PATH = "/Users/filiporlikowski/Documents/SEGPRD/project/pki/intermediate/crl/crl.pem"  #Path to the CRL (Certificate Revocation List) file
USER_CERTS_PATH = "/Users/filiporlikowski/Documents/SEGPRD/project/pki/users"
# Home route (returns a welcome message)
@app.route('/')
def home():
    return "Welcome to the Flask App!"

# JSON response route (returns a JSON response)
@app.route('/api')
def api():
    return jsonify({
        "message": "This is a simple API response",
        "status": "success"
    })

# Route with a dynamic parameter
@app.route('/hello/<name>')
def hello(name):
    return f"Hello, {name}!"

# Form submission route (GET and POST)
@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if request.method == 'POST':
        # Get data from the form
        user_name = request.form['name']
        return f"Form submitted! Hello, {user_name}."
    return '''
        <form method="POST">
            Name: <input type="text" name="name">
            <input type="submit" value="Submit">
        </form>
    '''

# Route for certificate revocation how to use
# curl -X POST -F "cert_path=/path/to/user_cert.pem" http://localhost:5000/revoke

# In this example, when a POST request is sent to /revoke, the certificate is revoked using the Intermediate CA's 
# private key, and the CRL is updated. You can later check this CRL in your NGINX configuration to prevent revoked 
# certificates from being used.

@app.route('/revoke', methods=['POST'])
def revoke_certificate():
    # Get the path to the certificate to revoke
    cert_path = request.form.get('cert_path')
    
    if not cert_path:
        return jsonify({"error": "Certificate path is required"}), 400
    
    # Revoke the certificate using OpenSSL
    revoke_command = [
        'openssl', 'ca', '-revoke', cert_path,
        '-keyfile', INTERMEDIATE_CA_KEY, '-cert', INTERMEDIATE_CA_CERT
    ]
    try:
        subprocess.run(revoke_command, check=True)
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to revoke certificate: {e}"}), 500

    # Generate an updated CRL after revocation
    crl_command = [
        'openssl', 'ca', '-gencrl', '-out', CRL_PATH,
        '-keyfile', INTERMEDIATE_CA_KEY, '-cert', INTERMEDIATE_CA_CERT
    ]
    try:
        subprocess.run(crl_command, check=True)
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to update CRL: {e}"}), 500

    # Optionally, integrate with an OCSP responder here to notify it about revocation.
    # This is typically done by interacting with an OCSP server to update the status.

    return jsonify({
        "message": "Certificate revoked and CRL updated successfully",
        "crl_path": CRL_PATH
    })
    
    
# In this example, the admin or system performs the recovery flow 
# by generating a new key pair, signing it, and revoking the old certificate. 
# The system then returns the new signed certificate 
# and updated CRL.

@app.route('/recover', methods=['POST'])
def recover_user():
    # User proves identity via secure means (admin verification in practice)
    user_name = request.form['name']
    
    # Generate new private key and CSR for the user
    new_user_key_path = f'/path/to/user_keys/{user_name}_new_private_key.pem'
    new_user_csr_path = f'/path/to/user_keys/{user_name}_new.csr'

    # Generate new private key
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-out', new_user_key_path, '-pkeyopt', 'rsa_keygen_bits:2048'])

    # Generate CSR
    subprocess.run(['openssl', 'req', '-new', '-key', new_user_key_path, '-out', new_user_csr_path, '-subj', f'/CN={user_name}'])

    # Sign the new CSR with the Intermediate CA
    new_signed_cert_path = f'/path/to/user_keys/{user_name}_new_signed_cert.pem'
    subprocess.run([
        'openssl', 'x509', '-req', '-in', new_user_csr_path, '-CA', INTERMEDIATE_CA_CERT,
        '-CAkey', INTERMEDIATE_CA_KEY, '-CAcreateserial', '-out', new_signed_cert_path, '-days', '365'
    ])
    
    # Revoke the old certificate and update the CRL (this step assumes the old cert is known)
    old_user_cert_path = request.form['old_cert_path']
    subprocess.run(['openssl', 'ca', '-revoke', old_user_cert_path, '-keyfile', INTERMEDIATE_CA_KEY, '-cert', INTERMEDIATE_CA_CERT])
    
    # Generate updated CRL
    crl_path = '/path/to/crl.pem'
    subprocess.run(['openssl', 'ca', '-gencrl', '-out', crl_path, '-keyfile', INTERMEDIATE_CA_KEY, '-cert', INTERMEDIATE_CA_CERT])

    return jsonify({
        'message': 'Identity recovered successfully',
        'new_signed_cert': new_signed_cert_path,
        'crl_path': crl_path
    })



# Render a simple HTML page with the render_template function (requires an HTML file in the templates folder)
@app.route('/about')
def about():
    return render_template('about.html')

# Run the application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
