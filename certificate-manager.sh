#!/usr/bin/env bash
set -e

SSL_DEFAULT_CONF=/etc/ssl/openssl.cnf
CA_SUBDIR=ca
OPENSSL_OPTS="-config $CA_SUBDIR/ca.conf -name current_ca"

ORGANIZATION=
DOMAIN=
CERT_VALID_DAYS=
CRL_VALID_DAYS=30
RSA_SIZE=2048

CLIENT_SSL=optional

function error_exit() {
    echo '*******'
    echo '******* Error, could not complete.' $1 $2 $3
    echo '*******'
    trap - EXIT
    exit 1;
}
trap error_exit EXIT INT TERM

show_help() {
cat << EOF
Usage: ${0##*/} [OPTIONS] ...

    Manages client and server self-signed certificates.
    For all the commands described below, ${0##*/} must
    be called in the directory where the certificates and CA
    are stored.

${0##*/} initialize [-o ORGANIZATION] [-r DAYS_CRL] [-s RSA_SIZE] DOMAIN

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

${0##*/} create CLIENTNAME PASSWORD DAYS_VALID

    Create a client certificate based on the current root CA.

    CLIENTNAME: a unique name for the certificate (typically
        the name of the user of this certificate)
    PASSWORD: the password required to import this certificate.
    DAYS_VALID: the validity in days of the certificate

${0##*/} revoke CLIENTNAME

    Revoke a client certificate. The .crl.pem file, containing
    all the revoked certificated is update.
    Typically, revoking a certificate means updating the configuration
    with a fresh version of this file.

${0##*/} nginx [-z SSL_CLIENT_OPTION]

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

EOF
}

create_client_certificate() {
    NAME=$1
    CLIENT_DIR=./Clients/$NAME
    CLIENT_BASENAME=$CLIENT_DIR/$NAME
    CLIENT_PASSWORD=$2
    CLIENT_CERTIFICATE_VALID_DAYS=$3

    [[ -z "$ORGANIZATION" ]] && ORGANIZATION=`cat $CA_SUBDIR/.ca_organization`
    [[ -z "$ORGANIZATION" ]] && error_exit 'Organization undefined, are you in a valid CA directory?'
    [[ -z "$DOMAIN_NAME" ]] && DOMAIN_NAME=`cat $CA_SUBDIR/.domain_name`
    [[ -z "$DOMAIN_NAME" ]] && error_exit 'Domain name undefined, are you in a valid CA directory?'

    CERT_CA_NAME=`cat $CA_SUBDIR/.cert_ca_basename`
    [[ -z "$CERT_CA_NAME" ]] && error_exit 'CA Root certificate undefined, are you in a valid CA directory?'


    echo Creating client certificate $NAME \(location $CLIENT_DIR \)

    [ -z "$CLIENT_CERTIFICATE_VALID_DAYS" ] && read -p "Days before this certificate expires: " CLIENT_CERTIFICATE_VALID_DAYS

    if [ -d "$CLIENT_DIR" ]; then
        echo "Error, client $NAME already exists as $CLIENT_DIR"
        exit 11
    fi
    if [ -d "$CLIENT_PASSWORD" ]; then
        echo "Error, no password set for client $NAME"
        exit 11
    fi

    mkdir -p $CLIENT_DIR

    echo ===== Generating the TLS client private key $CLIENT_BASENAME.key
    openssl genrsa -out $CLIENT_BASENAME.key 4096

    echo ===== Generating the TLS client CSR $CLIENT_BASENAME.csr
    SUBJ="/C=FR/ST=/L=/O=$ORGANIZATION/OU=Client Cert. $NAME/CN=$DOMAIN_NAME"
    openssl req -nodes -new -key $CLIENT_BASENAME.key -out $CLIENT_BASENAME.csr  -subj "$SUBJ"
    echo ===== Generating the TLS client certificate .crt

    echo openssl ca $OPENSSL_OPTS -keyfile $CERT_CA_NAME.key -cert $CERT_CA_NAME.crt -extensions usr_cert -notext -md sha1 -in $CLIENT_BASENAME.csr  -out $CLIENT_BASENAME.crt
    openssl ca $OPENSSL_OPTS -keyfile $CERT_CA_NAME.key -cert $CERT_CA_NAME.crt -extensions usr_cert -notext -md sha1 -in $CLIENT_BASENAME.csr  -out $CLIENT_BASENAME.crt

    openssl ca $OPENSSL_OPTS -keyfile $CERT_CA_NAME.key -cert $CERT_CA_NAME.crt  -gencrl -out $DOMAIN_NAME.crl.pem

    echo ===== Exporting the client certificate as a pkcs12 .p12 file
    openssl pkcs12 -nodes -export -out $CLIENT_BASENAME-FULL.pfx -inkey $CLIENT_BASENAME.key -in $CLIENT_BASENAME.crt -certfile $CERT_CA_NAME.crt -passout pass:$CLIENT_PASSWORD
    cp $CLIENT_BASENAME-FULL.pfx $CLIENT_BASENAME-FULL.p12
    echo ===== Exporting the client certificate as a full-fledged PEM
    openssl pkcs12 -in $CLIENT_BASENAME-FULL.pfx -out $CLIENT_BASENAME-FULL.pem -clcerts -passin pass:$CLIENT_PASSWORD -passout pass:$CLIENT_PASSWORD
    echo $CLIENT_PASSWORD >$CLIENT_BASENAME.password
    echo =====
    echo ===== Client certificate for $NAME now available in `realpath $CLIENT_DIR`
    echo ===== Use either `basename $CLIENT_BASENAME-FULL.pfx` or `basename $CLIENT_BASENAME-FULL.pem`
    echo ===== The validity for this certificate is $CLIENT_CERTIFICATE_VALID_DAYS days
    echo ===== The password to import this certificate is $CLIENT_PASSWORD
    echo =====
}

revoke_client_certificate() {
    NAME=$1
    CLIENT_DIR=./Clients/$NAME

    [[ -z "$DOMAIN_NAME" ]] && DOMAIN_NAME=`cat $CA_SUBDIR/.domain_name`
    [[ -z "$DOMAIN_NAME" ]] && error_exit 'Domain name undefined, are you in a valid CA directory?'

    CERT_CA_NAME=`cat $CA_SUBDIR/.cert_ca_basename`
    [[ -z "$CERT_CA_NAME" ]] && error_exit 'CA Root certificate undefined, are you in a valid CA directory?'

    openssl ca $OPENSSL_OPTS -keyfile $CERT_CA_NAME.key -cert $CERT_CA_NAME.crt    -revoke $CLIENT_DIR/$NAME.crt
    openssl ca $OPENSSL_OPTS -keyfile $CERT_CA_NAME.key -cert $CERT_CA_NAME.crt     -gencrl -out $DOMAIN_NAME.crl.pem

    echo =====
    echo ===== Client certificate $NAME revoked.
    echo ===== The file $DOMAIN_NAME.crl.pem has been updated.
    echo =====

}

initialize_ca() {
    DOMAIN_NAME=$1
    [[ -z "$ORGANIZATION" ]] && read -p "Your organization: " ORGANIZATION
    [[ -z "$DOMAIN_NAME" ]] && read -p "Your domain: " DOMAIN_NAME

    echo "Parameters:"
    echo " - Your domain name: " $DOMAIN_NAME
    echo " - Your organization: " $ORGANIZATION
    CERT_CA_NAME=$DOMAIN_NAME-rootCA
    VALIDDAYS=24000
    [ -z "$ORGANIZATION" ] && echo NO ORGANIZATION && exit 1

    mkdir -p ${CA_SUBDIR}/ca.db.certs   # Signed certificates storage
    touch ${CA_SUBDIR}/ca.db.index      # Index of signed certificates
    echo 01 > ${CA_SUBDIR}/ca.db.serial # Next (sequential) serial number

    cat /etc/ssl/openssl.cnf >${CA_SUBDIR}/ca.conf

    echo "" >>${CA_SUBDIR}/ca.conf
    echo "[ current_ca ]" >>${CA_SUBDIR}/ca.conf
    echo "dir = " ${CA_SUBDIR} >>${CA_SUBDIR}/ca.conf
    echo "default_crl_days = " $CRL_VALID_DAYS >>${CA_SUBDIR}/ca.conf
    echo 'crl = $dir/'$DOMAIN_NAME.crl.pem >>${CA_SUBDIR}/ca.conf

    cat>>${CA_SUBDIR}/ca.conf<<'EOF'
certs = $dir
new_certs_dir = $dir/ca.db.certs
database = $dir/ca.db.index
serial = $dir/ca.db.serial
RANDFILE = $dir/ca.db.rand
certificate = $dir/ca.crt
private_key = $dir/ca.key
default_md = md5
preserve = no
policy = generic_policy
default_days = 30

[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
EOF

    echo ===== Generating CA private key
    openssl genrsa $OPT -out $CERT_CA_NAME.key $RSA_SIZE
    echo ===== Generating CA certificate
    openssl req $OPT -nodes -x509 -new -nodes -key $CERT_CA_NAME.key -days $VALIDDAYS -out $CERT_CA_NAME.crt -subj "/C=/ST=/L=/O=$ORGANIZATION/OU=CA/CN=$DOMAIN_NAME"
    echo ===== Generating the certificate private key
    openssl genrsa $OPT -out $DOMAIN_NAME.key $RSA_SIZE
    echo ===== Generating TLS CSR
    openssl req $OPT -nodes -new -key $DOMAIN_NAME.key -out $DOMAIN_NAME.csr  -subj "/C=/ST=/L=/O=$ORGANIZATION/OU=CSR/CN=$DOMAIN_NAME"
    echo ===== Generating the TLS certificate based on the CA
    openssl x509 $OPT -req -in $DOMAIN_NAME.csr -CA $CERT_CA_NAME.crt -CAkey $CERT_CA_NAME.key -CAcreateserial -out $DOMAIN_NAME.crt -days $VALIDDAYS
    cat $DOMAIN_NAME.crt $CERT_CA_NAME.crt >$DOMAIN_NAME-chained-with-ca.crt

    openssl ca $OPENSSL_OPTS -keyfile $CERT_CA_NAME.key -cert $CERT_CA_NAME.crt     -gencrl -out $DOMAIN_NAME.crl.pem

    echo $DOMAIN_NAME >$CA_SUBDIR/.domain_name
    echo $CERT_CA_NAME >$CA_SUBDIR/.cert_ca_basename
    echo $ORGANIZATION >$CA_SUBDIR/.ca_organization

}

function create_nginx_config() {
    [[ -z "$DOMAIN_NAME" ]] && DOMAIN_NAME=`cat $CA_SUBDIR/.domain_name`
    [[ -z "$DOMAIN_NAME" ]] && error_exit 'Domain name undefined, are you in a valid CA directory?'
    CERT_CA_NAME=`cat $CA_SUBDIR/.cert_ca_basename`
    [[ -z "$CERT_CA_NAME" ]] && error_exit 'CA Root certificate undefined, are you in a valid CA directory?'

    SSL_CLIENT_CONFIG=""
    if [[ ! -z "$CLIENT_SSL" ]] ; then
        case "$CLIENT_SSL" in
        "on")
            SSL_CLIENT_CONFIG='  ssl_client_certificate /etc/nginx/ssl/'$CERT_CA_NAME'.crt;
  ssl_crl /etc/nginx/ssl/'$DOMAIN_NAME.crl.pem';
  ssl_verify_client on;'
            echo ' **** SSL client certificate is activated and mandatory'
        ;;
        "optional")
            SSL_CLIENT_CONFIG='  ssl_client_certificate /etc/nginx/ssl/'$CERT_CA_NAME'.crt;
  ssl_crl /etc/nginx/ssl/'$DOMAIN_NAME.crl.pem';
  ssl_verify_client optional;'
            echo ' **** SSL client certificate is activated but optional'
        ;;
        *)
            error_exit "Invalid ssl_verify_client value"
            ;;
        esac
    fi

    mkdir -p ./nginx
    echo "Creating nginx configuration in nginx/$DOMAIN_NAME"
    echo '
server {
  listen 80;
  listen 443 ssl;

  server_name '$DOMAIN_NAME';

  ssl_certificate /etc/nginx/ssl/'$DOMAIN_NAME'-chained-with-ca.crt;
  ssl_certificate_key /etc/nginx/ssl/'$DOMAIN_NAME'.key;

'"$SSL_CLIENT_CONFIG"'

  location / {
    proxy_pass         http://some_host:3000/;
  }
}
' >nginx/$DOMAIN_NAME
}

OPTIND=1 # Reset is necessary if getopts was used previously in the script.  It is a good idea to make this local in a function.
while getopts "hv:o:d:r:s:z:" opt; do
    case "$opt" in
        h)
            show_help
            exit 0
            ;;
        v)  verbose=$((verbose+1))
            ;;

        o)  ORGANIZATION=$OPTARG
        ;;

        d) DOMAIN=$OPTARG
        ;;


        r)  CRL_VALID_DAYS=$OPTARG
        ;;

        s) RSA_SIZE=$OPTARG
        ;;

        z) CLIENT_SSL=$OPTARG
        ;;

        '?')
            show_help >&2
            exit 1
            ;;
    esac
done
shift "$((OPTIND-1))" # Shift off the options and optional --.

VERB=$1 ; NAME=$2

if [[ -z "$VERB" ]] ; then
    show_help
    exit 1
fi

case "$VERB" in

"initialize")
    [ -z "$NAME" ] && show_help && exit 1
    initialize_ca $NAME
    ;;

"create")
    [ -z "$NAME" ] && show_help && exit 1
    PASSWORD=$3
    VALID_DAYS=$4
    create_client_certificate $NAME $PASSWORD $VALID_DAYS
    ;;

"revoke")
    [ -z "$NAME" ] && show_help && exit 1
    revoke_client_certificate $NAME
    ;;

"nginx")
    create_nginx_config
    ;;
*)
    show_help
    error_exit "Unknown command"
esac

trap - EXIT