from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/whoami")
def whoami():
    # Access the certificate headers passed by Nginx
    client_verify = request.headers.get('SSL-Client-Verify', 'no cert')
    client_dn = request.headers.get('SSL-Client-DN', 'no subject')
    client_cert = request.headers.get('SSL-Client-Cert', 'no certificate')

    # Return the certificate details in the response
    return jsonify({
        "status": client_verify,
        "subject": client_dn,
        "certificate": client_cert[:100] + "..."  # Just show a snippet for readability
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)