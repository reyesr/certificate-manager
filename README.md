## Certificate manager

This script manages the creation of RSA self-signing certificates:

- Initialize a Certificate Authority (CA) and a root certificate
- Create client certificates
- Revoke client certificate
- Generate an nginx configuration

## Using client certificates

Client certificates are mainly useful to provide an additional control over the access of a web location. 

A typical scenario would be to create specific client certificates to remote users, and revoking their access 
server-side without any modification of the web application. This script helps manage this workflow.

## Workflow example

### Initializing

First, let's create a new certificate:

    mkdir MyNewCA
    cd MyNewCA
    certificate_manager.sh -o "My Self Org" -c 24000 initialize www.example.com

At this point, the script asks a few questions about your organization and domain name. This last command
creates a root CA, and creates a TLS certificate based on this root. Check the files, you should see a list not unlike this one:

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

The CA database are a bunch of files used by openssl, it's not usually necessary except when you need to revoke client certificates: this helps keeping track of 
the created certificates and create a list of all the revoked ones. This is only useful to openssl, so you can ignore the `ca/` folder.

If you use Nginx, you will need the `www.example.com-chained-with-ca.crt` file: it's a
concat of the server certificate and the CA certificate, and this is the only format
(at the time of this writing) accepted by Nginx to provide chained certificates.

If you use apache2, you would rather use the following directives:
  SSLCertificateFile /etc/apache2/ssl/www.example.com.crt
  SSLCertificateKeyFile /etc/apache2/ssl/www.example.com.key
  SSLCACertificateFile /etc/apache2/ssl/www.example.com-rootCA.crt

Also, if you plan to use client certificate, do not forget to include the ./*.crl.pem file. It describes all the revoked client certificates, so it's very useful when you know that you may have to revoke a compromised certificate (rather than changing all the server and the client certificates).

### Creating a client certificate

Creating a new client certificate is rather easy:

    certificate-manager.sh create Joe s3cR3tp4ssw0rd 120

This creates a certificate for "Joe", with the password "s3cR3tp4ssw0rd". The certificate
expires 120 days later, so after this date, the ssl will be rejected by the server. The password is the import password, in other words, the user will need to set the password
when importing the certificated in the browser (but once it's imported, the password
is not needed anymore)

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
    
To install the client certificate in a browser, use the .pfx or .p12 file (Firefox wants a .pfx, and chrome wants a .p12, but it's the same format actually).
    
To have your client recognize with no security warning the server certificate, you
can additionnaly install the root certificate. For instance, on Ubuntu:
To install the certificate on an Ubuntu linux, 

    # You may need to "sudo apt-get install ca-certificates" first
    sudo cp www.example.com-rootCA.crt /usr/share/ca-certificates/local/
    sudo update-ca-certificates --fresh

### Revoking a certificate

To revoke a certificate before its normal expiration date, you just need to call:
    
    certificate-manager.sh revoke Joe

Joe is the same certificate user that we create earlier. By revoking it, the CA database
and the CRL file are updated. You need to update your web server with the new version
of ./www.example.com.crl.pem and any further request using Joe's client certificate
is going to be rejected by the server.


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
