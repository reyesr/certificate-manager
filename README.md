## Certificate manager

This script creates and manages self-signed certificates:

- Automatically creates CA-chained server certificates
- Creates a CA root certificate to be added to Windows/Linux/MacOS and browsers
- Transparently manages the CA database
- Creates and revokes client certificates
- Updates the revoked certificates CRL file for servers.
- Generate an nginx configuration
- One single bash script and no dependencies except openssl, ideal for Docker configurations
- Generate RSA 2048 or 4096

The certificate manager script creates in one command the full set of self-signed certificates and CA files; it
also provides a simple interface to create and revoke client certificates chained to the root CA.

## Using client certificates

While server certificates provide authentication and data confidentiality to the clients, client certificates
provides an additional authentication and security to the server directly at the transport protocol level.

It permits a refined access control without any modification at the application level.

This script easely manages the typical workflow of the creation and revoking of client certificates in a single command.

## Workflow example

### Initializing

First, let's create a new certificate:

    mkdir MyNewCA
    cd MyNewCA
    certificate_manager.sh initialize www.example.com

At this point, the script needs a few information asks a few questions about your organization and domain name. This command
creates a root CA and the server certificate for the www.example.com domain chained to the root. 
Check the files, you should see a list not unlike this one:

    $ find .
    .
    ./www.example.com-rootCA.crt     <- **The root certicate**
    ./www.example.com-rootCA.key     <- **and its secret key**
    ./ca                             <- **The CA database**
    ./ca/.ca_organization
    ./ca/ca.db.serial
    ./ca/.domain_name
    ./ca/ca.db.certs
    ./ca/ca.db.index
    ./ca/.cert_ca_basename
    ./ca/ca.conf
    ./www.example.com.key
    ./www.example.com-chained-with-ca.crt  <- **The chained server cert. for Nginx**
    ./www.example.com.crt            <- **The server certificate**
    ./www.example.com.crl.pem        <- **The CRL**
    ./www.srl
    ./www.example.com.csr

The root certificate and its secret key are the files that you should keep extra-safe, as they are used to create the server and client certificates.

The CA database is a set of files stores in the `ca/` folder, and are usually not required, except to
keep track of the client certificates and their revocation. 

If you use Nginx, you will need the `www.example.com-chained-with-ca.crt` file: it's a
concat of the server certificate and the CA certificate, and this is the only format
(at the time of this writing) accepted by Nginx to provide chained certificates.

If you use apache2, you would rather use the following directives:

    SSLCertificateFile /etc/apache2/ssl/www.example.com.crt
    SSLCertificateKeyFile /etc/apache2/ssl/www.example.com.key
    SSLCACertificateFile /etc/apache2/ssl/www.example.com-rootCA.crt

Also, if you plan to use client certificates, do not forget to include the ./*.crl.pem. 
This file lists all the revoked client certificates, so it's very useful when you know that 
you may have to revoke a compromised certificate (rather than changing all the server and the client certificates of
your users).

### Creating a client certificate

Creating a new client certificate is rather easy:

    certificate-manager.sh create Joe s3cR3tp4ssw0rd 120

This creates a certificate for "Joe", with the password "s3cR3tp4ssw0rd". The certificate
expires 120 days later, so after this date, the ssl will be rejected by the server. 
The password is typically asked when importing the certificate (once it's imported, clients that use a form
of certificate storage usually do not ask it again).

Let's see what files were created during this process:

    $ find ./Clients/Joe
    ./Clients/Joe
    ./Clients/Joe/Joe-FULL.pem    <- The certificate for Ubuntu
    ./Clients/Joe/Joe.crt
    ./Clients/Joe/Joe-FULL.pfx    <- The certificate for web browsers
    ./Clients/Joe/Joe-FULL.p12    <- A copy of the .pfx, but as .p12
    ./Clients/Joe/Joe.csr
    ./Clients/Joe/Joe.key
    ./Clients/Joe/Joe.password    <- A reminder of the import password
    
To install the client certificate in a browser, use the .pfx or .p12 file (Firefox wants a .pfx, while 
chrome wants a .p12, but it's the same format actually).
    
To ensure your client recognizes the server certificate (at least without a security warning), you
can additionnaly install the root certificate. For instance, on Ubuntu:
To install the certificate on an Ubuntu linux, 

    # You may need to "sudo apt-get install ca-certificates" first
    sudo cp www.example.com-rootCA.crt /usr/share/ca-certificates/local/
    sudo update-ca-certificates --fresh

Refer to your operating system documentation for the details of importing a certificate as trusted root, 
in any case you'll have to import the *-rootCA.crt file system-wide. 

### Revoking a certificate

To revoke a certificate before its normal expiration date, you just need to call:
    
    certificate-manager.sh revoke Joe

Joe is the same certificate user that we create earlier. By revoking it, the CA database
and the CRL file are updated. You need to update your web server with the new version
of ./www.example.com.crl.pem and any further request using Joe's client certificate
is going to be rejected by the server.

### Using curl

Use the `--cert` option to use the client certificate. You may need to add the password for the
client to the command line.

    curl --cert ./Clients/Joe/Joe-FULL.pem:s3cR3tp4ssw0rd https://www.example.com
     
## Usage

Usage: certificate-manager.sh [OPTIONS] ...

    Manages client and server self-signed certificates.
    For all the commands described below, ${0##*/} must
    be called in the directory where the certificates and CA
    are stored.

certificate-manager.sh initialize [-o ORGANIZATION] [-r DAYS_CRL] [-s RSA_SIZE] DOMAIN

    Initialize the CA and the certificate in the current directory.
    The current directory must be empty.

    DOMAIN: The fully qualified domain name, eq www.example.com

    -o ORGANIZATION: Your organization, as it should appear in the
       certificate
    -r DAYS_CRL: maximum number of days to update the CRL (revoked)
       Default is 30, but you may want to increase it, given that if
       you do not update the crl file on your server in this period of
       time, all client certificates will be rejected. Boom.
    -s RSA_SIZE: The RSA key size (default 2048)

certificate-manager.sh create CLIENTNAME PASSWORD DAYS_VALID

    Create a client certificate based on the current root CA.

    CLIENTNAME: a unique name for the certificate (typically
        the name of the user of this certificate)
    PASSWORD: the password required to import this certificate.
    DAYS_VALID: the validity in days of the certificate

certificate-manager.sh revoke CLIENTNAME

    Revoke a client certificate. The .crl.pem file, containing
    all the revoked certificated is update.
    Typically, revoking a certificate means updating the configuration
    with a fresh version of this file.

certificate-manager.sh nginx [-z SSL_CLIENT_OPTION]

    Creates a basic nginx configuration that you can uses the
    self-signed certificate.

    -z SSL_CLIENT_OPTION: either "on" or "optional" (unset
        means no client ssl configuration).
        If "on", the web client is required to provide a valid
        (ie. not revoked) client certificate, or reject the https
        request (default is an http error code 400)
        If "optional", the server requests a certificate, but
        the requested content is served even if no valid certificate
        is provided (this can then be tested at the application level)


## License

(C) Copyright 2015 Rodrigo Reyes https://github.com/reyesr

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
