from flask import Flask, jsonify, request, render_template, send_from_directory, logging
import os
import subprocess
import shutil

# Initialize the Flask application
app = Flask(__name__)

# Paths for the PKI directories  I HAVE TO READ MORE ABOUT THE PROCESS OF CREATING THE USER PRIVATE KEYS ETC
# AND WITH WHAT AND WHAT SHOULD BE SIUGNED BY THE INTERMEDIATE CA OR ROOT CA

# Get base directory dynamically (where this script is running)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# PKI Paths
PKI_PATH = os.path.join(BASE_DIR, 'pki')
ROOT_CA_PATH = os.path.join(PKI_PATH, 'rootCA')
INTERMEDIATE_CA_PATH = os.path.join(PKI_PATH, 'intermediate')
USER_CERTS_PATH = os.path.join(PKI_PATH, 'users')

# Intermediate CA Files
INTERMEDIATE_CA_CERT = os.path.join(INTERMEDIATE_CA_PATH, 'certs', 'intermediateCA.crt')
INTERMEDIATE_CA_KEY = os.path.join(INTERMEDIATE_CA_PATH, 'private', 'intermediateCA.key')
CRL_PATH = os.path.join(INTERMEDIATE_CA_PATH, 'crl', 'crl.pem')

# Ensure directories exist

# Ensure the necessary directories exist
os.makedirs(USER_CERTS_PATH, exist_ok=True)

# Helper function to execute shell commands (e.g., OpenSSL)
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return e.stderr.decode('utf-8')

# User onboarding route

#EXAMPLE USAGE

#curl -X POST -F "name=john_doe" http://127.0.0.1:5000/create_user

# Enable logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/create_user', methods=['POST'])
def create_user():
    user_name = request.form['name']
    user_dir = os.path.join(USER_CERTS_PATH, user_name)

    # Create a directory for the user if it doesn't exist
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
        logging.debug(f"Created directory: {user_dir}")

    # Step 1: Generate the user's private key
    key_file = os.path.join(user_dir, f'{user_name}.key')
    result = run_command(f"openssl genpkey -algorithm RSA -out {key_file}")
    logging.debug(f"Private key creation result: {result}")

    # Step 2: Generate the CSR (Certificate Signing Request)
    csr_file = os.path.join(user_dir, f'{user_name}.csr')
    result = run_command(f"openssl req -new -key {key_file} -out {csr_file} -subj \"/CN={user_name}\"")
    logging.debug(f"CSR creation result: {result}")

    # Step 3: Sign the CSR with Intermediate CA to issue the certificate
    cert_file = os.path.join(user_dir, f'{user_name}.crt')
    result = run_command(f"openssl ca -in {csr_file} -out {cert_file} -cert {INTERMEDIATE_CA_CERT} -keyfile {INTERMEDIATE_CA_KEY}")
    logging.debug(f"Certificate creation result: {result}")

    return jsonify({
        'message': f'Certificate created for {user_name}!',
        'status': 'success',
        'user_name': user_name,
        'certificate': cert_file
    })

# User revocation route
@app.route('/revoke_user', methods=['POST'])
def revoke_user():
    user_name = request.form['name']
    user_dir = os.path.join(USER_CERTS_PATH, user_name)

    if not os.path.exists(user_dir):
        return jsonify({
            'message': f'User {user_name} not found.',
            'status': 'error'
        })

    cert_file = os.path.join(user_dir, f'{user_name}.crt')

    # Step 1: Revoke the certificate by adding to CRL (Certificate Revocation List)
    crl_file = os.path.join(INTERMEDIATE_CA_PATH, 'crl', 'crl.pem')
    run_command(f"openssl ca -revoke {cert_file} -crl_reason superseded")
    run_command(f"openssl ca -gencrl -out {crl_file}")

    # Optional: Add to OCSP if required

    # Clean up the user's files (optional)
    shutil.rmtree(user_dir)

    return jsonify({
        'message': f'Certificate for {user_name} has been revoked!',
        'status': 'success'
    })

# List all users' certificates
@app.route('/list_users', methods=['GET'])
def list_users():
    users = []
    for user in os.listdir(USER_CERTS_PATH):
        user_dir = os.path.join(USER_CERTS_PATH, user)
        if os.path.isdir(user_dir):
            cert_file = os.path.join(user_dir, f'{user}.crt')
            if os.path.exists(cert_file):
                users.append({
                    'user_name': user,
                    'certificate': cert_file
                })
    return jsonify(users)

# Serve the certificate file for download (optional)
@app.route('/download_certificate/<user_name>', methods=['GET'])
def download_certificate(user_name):
    user_dir = os.path.join(USER_CERTS_PATH, user_name)
    cert_file = os.path.join(user_dir, f'{user_name}.crt')
    if os.path.exists(cert_file):
        return send_from_directory(user_dir, f'{user_name}.crt', as_attachment=True)
    else:
        return jsonify({
            'message': f'Certificate for {user_name} not found.',
            'status': 'error'
        })
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


# Run the application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
