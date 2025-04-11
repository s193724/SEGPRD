################## 1° Phase - Root Setup ##################

# 1.0 - Create the root CA directory structure
mkdir rootCA
cd rootCA
mkdir certs crl newcerts private
chmod 700 private   # Set permissions to the private directory (700 = rwx------)
ls -la private      # To show the permissions of the directory
touch index.txt
echo 1000 > serial
# nano openssl_rootCA.cnf # Editing the openssl_rootCA.cnf file to set the default values for the root CA

# 1.1 - Create the root CA RSA private key with a length of 4096 bits
openssl genrsa -aes256 -out private/rootCA.key.pem 4096

# 1.2 - Set the permissions of the private key to read for the user only
chmod u=r private/rootCA.key.pem
ls -la private/rootCA.key.pem 
#chmod 400 private/rootCA.key.pem

# 1.3 - Create the root CA certificate using the private key from the previous step.
# It asks for several details, including the passphrase of the private key. Enter all the details to generate the
# root certificate. Keep a record of the details, because the same information is required to create Certificate
# Signing Requests (CSRs) for all other certificates for the intermediate CAs (we're using strict policies)

# NOTE: La chiave pubblica non viene generata esplicitamente come file separato. Quando crei il certificato della Root CA (passaggio 1.3 nel tuo script), la chiave pubblica viene inclusa nel certificato stesso.
# Il certificato della Root CA contiene: La chiave pubblica; Informazioni sulla CA (nome, durata, ecc.); la firma digitale 
# generata con la chiave privata.
# Quindi, quando distribuisci il certificato della Root CA ai dispositivi (come browser o server), stai effettivamente distribuendo la chiave pubblica della Root CA. Questa chiave pubblica verrà utilizzata dai dispositivi per verificare la validità dei certificati firmati dalla Root CA o dalle sue subordinate.
openssl req -config openssl_rootCA.cnf -new -x509 -key private/rootCA.key.pem -days 3650 -sha256 -extensions v3_root_ca -out certs/rootCA.cert.pem

# 1.4 - Set the permissions of the root CA certificate to read for the user only
chmod 444 certs/rootCA.cert.pem # Permission is equivalent of (r--r--r--)
ls -la certs/rootCA.cert.pem

# 1.5 - Verify the root CA certificate
openssl x509 -noout -text -in certs/rootCA.cert.pem

# End of the 1° Phase: now the Root Certificate can be be deployed to all devices (e.g., web browsers, users) 
# in the internal network

################## 2° Phase - Intermediate CA Setup ##################

# 2.0 - Create the intermediate CA directory structure
cd ..
mkdir /intermediateCA
cd /intermediateCA
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber
# There are only few changes to be made in the openssl_rootCA.cnf file for the intermediate CA;
# That's why we copy the openssl_rootCA.cnf file from the root CA directory to the intermediate CA directory
cp ../rootCA/openssl_rootCA.cnf .

# 2.1 - Create the intermediate CA RSA private key with a length of 4096 bits
openssl genrsa -aes256 -out private/intermediateCA.key.pem 4096
chmod 400 private/intermediateCA.key.pem

# 2.2 - Create the intermediate CA certificate signing request (CSR) using the private key from the previous step.
# Note: In this case, we're creating a CSR (a Request!!) for the intermediate CA, which will be signed by the root CA.
# The CSR contains the public key and the information about the intermediate CA, but it is not a certificate yet.
# The CSR is signed with the private key of the intermediate CA, and it will be sent to the root CA for signing.
# The root CA will verify the CSR and sign it, creating the intermediate CA certificate.
# This passage is different from the one in the root CA, where we created a **self-signed** certificate.
openssl req -config openssl_IntermediateCA.cnf -new -sha256 -key private/intermediateCA.key.pem -out csr/intermediateCA.csr.pem

# 2.3 - The root CA accept the CSR and signs the intermediate CA public key generating the intermediate CA certificate
# We store this certificate in the certs directory of the intermediate CA
# It will be prompted for the passphrase of the root CA private key and the details of the intermediate CA certificate and asked
# if you want to sign the CSR. 
# Then the database (index.txt) and the serial number of the root CA will be updated
cd ../rootCA
openssl ca -config openssl_rootCA.cnf -extensions v3_intermediate_ca -days 1825 -notext -md sha256 -in ../intermediateCA/csr/intermediateCA.csr.pem -out ../intermediateCA/certs/intermediateCA.cert.pem

# 2.4 Check the intermediate CA certificate generated
openssl x509 -noout -text -in ../intermediateCA/certs/intermediateCA.cert.pem

# 2.5 Check if the chain of trust is valid
openssl verify -CAfile certs/rootCA.cert.pem ../intermediateCA/certs/intermediateCA.cert.pem

"""
When an application (e.g., a web browser) tries to verify a certificate signed by the Intermediate CA, it must
also verify the Intermediate certificate against the Root certificate. To complete the Chain of Trust, create
a CA certificate chain to present to the application.
To create the CA certificate chain, concatenate the Intermediate and Root certificates together (the order
does not matter).
"""
# 2.6 - Create the CA certificate chain
# NOTE: If we deployed the Root Certificate to ALL devices in your internal network, then the chain file only needs to contain the Intermediate certificate
# In my case yes, I deployed the Root Certificate in my device, with this command maybe:
# sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/rootCA.cert.pem
# Or using the Keychain Access:
#	1.	Open Keychain Access
#	2.	Drag your ca.cert.pem into System → Certificates
#	3.	Double-click it, expand Trust, set “When using this certificate” to Always Trust
# Anyway in this case we create the chain file with the Root CA certificate and the Intermediate CA certificate because
# when we use OpenSSL it won’t magically use the system trust store unless you set that up explicitly.
cat certs/rootCA.cert.pem ../intermediateCA/certs/intermediateCA.cert.pem > ../intermediateCA/certs/full-chain.cert.pem
# cat ../intermediateCA/certs/intermediateCA.cert.pem > ../intermediateCA/certs/int-chain.cert.pem
chmod 444 ../intermediateCA/certs/full-chain.cert.pem

# End of the 2° Phase: now ou Intermediate CA is ready to start issuing Subscriber Certificates.

################## 3° Phase - Server Subscriber Certificate Setup ##################
"""
The first step depends on the Subscriber who needs a signed certificate. They can ask you to either create
the certificate for them (including the private key!), or they create one themselves and send a Certificate
Signing Request (CSR) file to you.
The verification of the CSR is performed by the Registration Authority, while the actual signing of the
certificate is performed by the Certification Authority.
"""
# 3.0 - Create the subscriber directory. In this case we just need to store the server1 certificate, key, CSR and chain
cd ../intermediateCA
mkdir ../server1

# 3.1 - Create the server private key with a length of 2048 bits Our Root and Intermediate pairs are 4096 bits. 
# Server and client certificates normally expire after one year, so we can safely use 2048 bits instead, as is common on the Internet.
openssl genrsa -aes256 -out ../server1/server1.key.pem 2048
chmod 400 ../server1/server1.key.pem

# 3.2 - Create the server certificate signing request (CSR) using the private key
# Note: For server certificates, the Common Name must be a fully qualified domain name (e.g.,
# www.example.com).
openssl req -config openssl_IntermediateCA.cnf -key ../server1/server1.key.pem -new -sha256 -out ../server1/server1.csr.pem
# We virtually send this request to the Intermediate CA, which will verify the request and sign it.
cp ../server1/server1.csr.pem csr

# 3.3 - Sign the server certificate request with the intermediate CA
openssl ca -config openssl_IntermediateCA.cnf -extensions server_cert -days 375 -notext -md sha256 -in csr/server1.csr.pem -out certs/server1.cert.pem
chmod 444 certs/server1.cert.pem
# We virtually send this certificate to the Subscriber, who will install it on the server.
cp certs/server1.cert.pem ../server1
chmod 444 ../server1/server1.cert.pem

# 3.4 - Verify the server certificate
openssl x509 -noout -text -in ../server1/server1.cert.pem

# 3.5 - Verify the chain of trust for the server1 certificate
# Note: in this case we are verifying all the chain because ca-chain.cert.pem contains both the Root CA and the Intermediate CA certificates
# but in reality we will already have the Root CA certificate installed in the devices (e.g., web browsers, users), so we can just verify the Intermediate chain
openssl verify -CAfile certs/full-chain.cert.pem ../server1/server1.cert.pem

# 3.6 - Create the server certificate chain
# NOTE: In order to not have problems with the alignment between the key and the certificate, we need to specify **in Order** the chain of the certificates
# So in this case, the server1 certificate is the first one, then the intermediate CA certificate. The root is not needed because it will be installed in the devices
cat ../server1/server1.cert.pem certs/intermediateCA.cert.pem > ../server1/server1-chain.cert.pem

################## 4° Phase - Setting up the CRL (Certificate Revocation List) ##################
# Before starting:
# To make the clients check for the CRL, we need to update in the config file the section
# server_crt with: crlDistributionPoints = URI:http://localhost/intermediateCA.crl when generating a certificate
mkdir ../server_with_clr_check
openssl genrsa -aes256 -out ../server_with_clr_check/server_with_clr_check.key.pem 2048
openssl req -config openssl_IntermediateCA.cnf -key ../server_with_clr_check/server_with_clr_check.key.pem -new -sha256 -out ../server_with_clr_check/server_with_clr_check.csr.pem
cp ../server_with_clr_check/server_with_clr_check.csr.pem csr
# NOTE: in this case we use the extension server_cert_with_san_crl_ocsp because we need to add the CRL and OCSP information in the certificate
openssl ca -config openssl_IntermediateCA.cnf -extensions server_cert_with_san_crl_ocsp -days 375 -notext -md sha256 -in csr/server_with_clr_check.csr.pem -out certs/server_with_clr_check.cert.pem
cp certs/server_with_clr_check.cert.pem ../server_with_clr_check
cat ../server_with_clr_check/server_with_clr_check.cert.pem certs/intermediateCA.cert.pem > ../server_with_clr_check/server_with_clr_check-chain.cert.pem
openssl rsa -in ../server_with_clr_check/server_with_clr_check.key.pem -out ../server_with_clr_check/server_with_clr_check_decrypted.key.pem

####### UNDERSTAND BETTER why it doesn't give an error even if the CRL is not available
# Once done this, we can check if the certificate has the CRL distribution point by ispecting the certificate
# and see if there is this section X509v3 CRL Distribution Points:
openssl x509 -in ../server_with_clr_check/server_with_clr_check.cert.pem -noout -text

# 4.1 Revoking a certificate
cd ../intermediateCA
openssl ca -config openssl_IntermediateCA.cnf -revoke certs/server_with_clr_check.cert.pem

# 4.2 - Generate the CRL (it will generate it from the update of the database)
openssl ca -config openssl_IntermediateCA.cnf -gencrl -out crl/intermediateCA.crl

# 4.3 View the content of the CRL
openssl crl -in crl/intermediate.crl -text -noout

# Or we can start a web server to serve the CRL file.
python3 -m http.server 8000 --directory crl/
# Then we will need to contact http://localhost:8000/intermediateCA.crl
# This should be the real address

################## 5° Phase - Setting up OCSP (Online Certificate Status Protocol) ##################

# As we did for the CRL, also for OCSP, we need to add in the config file the section 
# authorityInfoAccess = OCSP;URI:http://localhost/ocsp
# And then we need to sign another certificate with this config file that has this section
# (there won't be reported again the steps to generate another certificate with this properties)
# After we created the certificate with the information of the OCSP, we can check if the certificate has this section:
openssl x509 -in ../server_with_ocsp_check/server_with_ocsp_check.cert.pem -noout -text

# Once done the previous step, we can start configuring the OCSP server, by doing the following steps
# 5.1 Creating a key for the OCSP server
openssl genrsa -aes256 -out ../ocsp_server/ocsp_server.key.pem 4096

# 5.2 Creating a CSR request in order to issue a OCSP certificate
openssl req -config openssl_IntermediateCA.cnf -new -sha256 -key ../ocsp_server/ocsp_server.key.pem -out ../ocsp_server/ocsp_server.csr.pem
cp ../ocsp_server/ocsp_server.csr.pem csr       # Moving the CSR request to the IntermediateCA

# 5.3 Validating and issuing the certificate
openssl ca -config openssl_IntermediateCA.cnf -extensions ocsp -days 375 -notext -md sha256 -in csr/ocsp_server.csr.pem -out certs/ocsp_server.cert.pem
cp certs/ocsp_server.cert.pem ../ocsp_server

# 5.4 Checking if in the certificate is reported that its usage is:
# X509v3 Extended Key Usage: critical OCSP Signing
openssl x509 -in ../ocsp_server/ocsp_server.cert.pem -noout -text

# 5.5 - Create the OCSP responder certificate chain
cat ../ocsp_server/ocsp_server.cert.pem certs/intermediateCA.cert.pem > ../ocsp_server/ocsp_server-chain.cert.pem

# 5.6 - Running an OCSP responder
# NOTE: The OCSP responder must be running on another server, so we need to copy the OCSP responder certificate and the private key to that OCSP server
# -port Listen on port 2560 locally
# -text Print request/response in human-readable form (for debugging)
# -index The CA's index file — this tracks issued/revoked certs
# -CA chain used to validate the OCSP signer
# -rkey Private key of the OCSP responder certificate
# -rsigner OCSP responder certificate
# -nrequest Quit after serving 2 requests (useful for testing)
openssl ocsp \
    -port 2560 \
    -text \
    -index index.txt \
    -CA ../ocsp_server/ocsp_server-chain.cert.pem \
    -rkey ../ocsp_server/ocsp_server.key.pem \
    -rsigner ../ocsp_server/ocsp_server.cert.pem \
    -nrequest 2

# 5.7 - Check the OCSP response with the OCSP responder
openssl ocsp \
  -issuer certs/intermediateCA.cert.pem \
  -cert ../server1/server1.cert.pem \
  -url http://localhost:2560 \
  -header Host=localhost:2560 \
  -no_nonce


################## 6° Phase - Creating a User Certificate ##################
cd ../intermediateCA
mkdir ../client1

# 6.1 - Create the server private key with a length of 2048 bits Our Root and Intermediate pairs are 4096 bits. 
# Server and client certificates normally expire after one year, so we can safely use 2048 bits instead, as is common on the Internet.
openssl genrsa -aes256 -out ../client1/client1.key.pem 2048
chmod 400 ../client1/client1.key.pem

# 6.2 - Create the server certificate signing request (CSR) using the private key
# Note: For server certificates, the Common Name must be a fully qualified domain name (e.g.,
# www.example.com).
openssl req -config openssl_IntermediateCA.cnf -key ../client1/client1.key.pem -new -sha256 -out ../client1/client1.csr.pem
# We virtually send this request to the Intermediate CA, which will verify the request and sign it.
cp ../client1/client1.csr.pem csr

# 6.3 - Sign the server certificate request with the intermediate CA
openssl ca -config openssl_IntermediateCA.cnf -extensions usr_cert -days 375 -notext -md sha256 -in csr/client1.csr.pem -out certs/client1.cert.pem
chmod 444 certs/client1.cert.pem
# We virtually send this certificate to the Subscriber, who will install it on the server.
cp certs/client1.cert.pem ../client1
chmod 444 ../client1/client1.cert.pem

# 6.4 - Verify the client certificate
openssl x509 -noout -text -in ../client1/client1.cert.pem

# 6.5 - Verify the chain of trust for the client1 certificate
# Note: in this case we are verifying all the chain because ca-chain.cert.pem contains both the Root CA and the Intermediate CA certificates
# but in reality we will already have the Root CA certificate installed in the devices (e.g., web browsers, users), so we can just verify the Intermediate chain
openssl verify -CAfile certs/full-chain.cert.pem ../client1/client1.cert.pem

# 6.6 - Create the server certificate chain
# NOTE: In order to not have problems with the alignment between the key and the certificate, we need to specify **in Order** the chain of the certificates
# So in this case, the client1 certificate is the first one, then the intermediate CA certificate. The root is not needed because it will be installed in the devices
cat ../client1/client1.cert.pem certs/intermediateCA.cert.pem > ../client1/client1-chain.cert.pem

# 6.7 - Create the PKCS12 file
# NOTE: The PKCS#12 format is a binary format for storing the server certificate, any intermediate certificates, and the private key in one encryptable file.
# The PKCS#12 file is used to import and export certificates and private keys on different platforms, such as Windows, macOS, and Linux.
# The PKCS#12 file is also used to import and export certificates and private keys in web browsers, such as Chrome, Firefox, and Safari.
cd ../client1

openssl pkcs12 -export \
  -in client1.cert.pem \
  -inkey client1.key.pem \
  -certfile client1-chain.cert.pem \
  -out client1.p12 \
  -name "Cert mTLS di Filippo"

# In order to have the prompt from the browser to use the certificate, we need to add this certificate we just created in the Keychain Access
# Then when we will contact the server, the browser will ask us to use this certificate
# Once done the connection with the server, we're authenticated!!