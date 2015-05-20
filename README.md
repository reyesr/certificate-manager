## Certificate manager

This script creates and manages self-signed certificates:

- Initializes and manages the CA database
- Automatically creates server certificates
- Creates and revokes client certificates
- Updates the revoked certificates CRL file for servers.
- Generate an nginx configuration
- One single bash script and no dependencies except openssl, ideal for Docker configurations
- Generate RSA 2048 by default (but configurable to any key size)

The certificate manager script creates in one command the full set of self-signed certificates and CA files; it
also provides a simple interface to create and revoke client certificates chained to the root CA.

## Using client certificates

While server certificates provide authentication and data confidentiality to the clients, client certificates
provides an additional authentication and security to the server directly at the transport protocol level.

It permits a refined access control without any modification at the application level.

This script easely manages the typical workflow of the creation and revoking of client certificates in a single command.

## Workflow example

### Initializing

First, let's create a new certificate. To do that, we shall start in a fresh directory, and we're going to install
there a new CA.

    mkdir MyNewCA
    cd MyNewCA
    certificate_manager.sh initialize

At this point, the script needs a few information asks a few questions about your organization and domain name. This command
creates a root CA.

Check the files, you should see a list not unlike this one:

    ./rootCA.crt            <- **The ROOT certificate**
    ./rootCA.key            <- **and its secret key**
    ./crl.pem
    ./ca                    <- **The CA database**
    ./ca/ca.conf
    ./ca/index.txt
    ./ca/serial
    ./ca/.ca_organization
    

The root certificate and its secret key are the files that you should keep extra-safe, as they are used to create the server and client certificates, 
and revoke them.

The CA database is a set of files stores in the `ca/` folder, and are usually not required, except to
keep track of the client certificates and their revocation. 

### Creating a server certificate

To add a new server certificate (eg, for the https protocol on a web server), just use the `create-server` parameter, 
along with the domain name to protect, and answer a few interactive question. 

    certificate-manager.sh create-server "www.example.org"

Note that the creation can run without any interactive question is all the information is provided on the command
line. The certificate is created in the Servers subdirectory. You should find this folder structure:

    ./Servers
    ./Servers/www.example.org_20150520
    ./Servers/www.example.org_20150520/www.example.org.key
    ./Servers/www.example.org_20150520/www.example.org-chained-with-ca.crt
    ./Servers/www.example.org_20150520/www.example.org.crt
    ./Servers/www.example.org_20150520/www.example.org.csr
    ./Servers/www.example.org_20150520/info
    ./Servers/www.example.org_20150520/nginx
    ./Servers/www.example.org_20150520/nginx/www.example.org

Note that the directory that contains all the certificate files contain the date of creation. This is to avoid
mixing the certificates when you issue it again.

The certificate is the www.example.org.crt, and you can use it right away on your server.

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

    certificate-manager.sh create-client "John Doe" s3cR3t 120

This creates a certificate for "Joe", with the password "s3cR3t". The certificate
expires 120 days later, so after this date, the ssl will be rejected by the server. 
The password is typically asked when importing the certificate (once it's imported, clients that use a form
of certificate storage usually do not ask it again).

Let's see what files were created during this process:

    Clients/John_Doe_20150521/John_Doe_20150521.csr
    Clients/John_Doe_20150521/John_Doe_20150521-FULL.pem        <- The certificate for Ubuntu
    Clients/John_Doe_20150521/John_Doe_20150521-FULL.pfx        <- The certificate for web browsers
    Clients/John_Doe_20150521/John_Doe_20150521-FULL.p12        <- A copy of the .pfx, but as .p12
    Clients/John_Doe_20150521/John_Doe_20150521.password        <- A reminder of the import password
    Clients/John_Doe_20150521/John_Doe_20150521.crt
    Clients/John_Doe_20150521/John_Doe_20150521.key
    
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
    
    certificate-manager.sh revoke-client ./Clients/John_Doe_20150521
    
As you can see, it's just a matter of calling "revoke-client" with the path to the folder that contains the
client certificate.
    
When it gets revoked, the CA database and the CRL file are updated. You need to update your web server with 
the new version of the CRL file (namely crl.pem) and any further request using Joe's client certificate
is going to be rejected by the server.

### Using curl

Use the `--cert` option to use the client certificate. You may need to add the password for the
client to the command line.

    curl --cert ./Clients/Joe/Joe-FULL.pem:s3cR3tp4ssw0rd https://www.example.com
     
## Usage

    Usage: certificate-manager.sh [OPTIONS] ...
    
        Manages client and server self-signed certificates.
        For all the commands described below, certificate-manager.sh must
        be called in the directory where the certificates and CA
        are stored.
    
    certificate-manager.sh initialize [-s KEY_SIZE] ORGANIZATION [DEFAULT-CERT-DAYS] [DEFAULT-CRL-DAYS]
    
        Initialize the CA and the certificate in the current directory.
        The current directory must be empty.
    
        ORGANIZATION: Your organization, as it should appear in the
           CA certificate
        DEFAULT-CERT-DAYS: The number of days this CA certificate should
           be valid.
        DEFAULT-CRL-DAYS: maximum number of days to update the CRL (revoked)
           Default is 30, but you may want to increase it, given that if
           you do not update the crl file on your server in this period of
           time, all client certificates will be rejected. Boom.
    
        -s KEY_SIZE: The RSA key size (default 2048)
    
    certificate-manager.sh create-server [-s KEY_SIZE] [-z SSL_CLIENT] DOMAIN [DAYS_VALID]
    
        Create a client certificate based on the current root CA. It also creates
        an example nginx configuration file ready to use (or modify).
    
        DOMAIN: The fully qualified domain name, eq www.example.com
    
        DAYS_VALID: the validity in days of the certificate
        -s KEY_SIZE: The RSA key size (default 2048)
    
        [for nginx]
        -z SSL_CLIENT_OPTION: either "on" or "optional" (unset
        means no client ssl option is added in the nginx configuration).
        If "on", the web client is required to provide a valid
        (ie. not revoked) client certificate, or reject the https
        request (default is an http error code 400)
        If "optional", the server requests a certificate, but
        the requested content is served even if no valid certificate
        is provided (this can then be tested at the application level)
    
    
    certificate-manager.sh create-client [-s KEY_SIZE] [CLIENTNAME] [PASSWORD] [DAYS_VALID]
    
        Create a client certificate based on the current root CA. If CLIENTNAME,
        PASSWORD, or DAYS_VALID are not provided, they are asked for in the
        interactive console.
    
        CLIENTNAME: a unique name for the certificate (typically
            the name of the user of this certificate)
        PASSWORD: the password required to import this certificate.
        DAYS_VALID: the validity in days of the certificate
    
        -s KEY_SIZE: The RSA key size (default 2048)
    
    certificate-manager.sh revoke-client CERT-FOLDER
    
        Revoke a client certificate. The .crl.pem file, containing
        all the revoked certificated is update.
        Typically, revoking a certificate means updating the configuration
        with a fresh version of this file.
    
        CERT-FOLDER the path to the folder where the client certificate is stored.
           This folder is typically stored in Clients/.
           For instance ./Clients/John_Doe_20150928


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
