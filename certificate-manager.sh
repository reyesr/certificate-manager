#!/usr/bin/env bash
set -e -u

CA_SUBDIR=ca
CA_FILENAME=rootCA
CRL_FILE=crl.pem

OPENSSL_OPTS="-config $CA_SUBDIR/ca.conf -name current_ca"

# ORGANIZATION is overridden by the -o option
ORGANIZATION=
OPT_ORGANIZATION=o
# DOMAIN is overriden by the -d option
DOMAIN=
OPT_DOMAIN=d
# CERT_VALID_DAYS is overriden by the -g option
CERT_VALID_DAYS=
OPT_CERT_VALID_DAYS=g
# CRL_VALID_DAYS is overriden by the -r option
CRL_VALID_DAYS=
OPT_CRL_VALID_DAYS=r
# RSA_SIZE is overriden by the -s option
RSA_SIZE=2048
OPT_RSA_SIZE=s
# CLIENT_SSL is overriden by the -z option
CLIENT_SSL=optional
OPT_CLIENT_SSL=z
# SILENT is overriden by the -y option
SILENT=
OPT_SILENT=y
# SUBJECT is overridden by -f option
SUBJECT=
OPT_SUBJECT=f

function error_exit() {
    if [[ ! -z ${1:-''} ]] ; then
        echo "Error:" ${1:-''}
        echo "Please type '"${0##*/} "-h' for help"
    fi
    echo "Aborted."
    trap - EXIT
    exit 1;
}
trap error_exit EXIT INT TERM

function normal_exit {
    trap - EXIT
    exit 0;
}

function ask_string() {
    local QUESTION="${1:-}"
    local DEFAULTVALUE="${2:-}"
    local ANSWER=""
    read -p "$QUESTION [$DEFAULTVALUE]: " ANSWER
    if [[ -z "$ANSWER" ]] ; then
        echo -n "$DEFAULTVALUE"
    else
        echo -n "$ANSWER"
    fi
}

function ask_subject() {
    local DEFAULTCN="${1:-}"
    local O="${2:-}"
    local CNHINT="${3:-}"
    local CNINFO="${4:-}"
    [[ -z "$CNINFO" ]] && CNINFO="e.g. server FQDN or YOUR name"
    local DEFAULTORG=""
    [[ -z "$DEFAULTORG" && -f "$CA_SUBDIR/.ca_organization" ]] && DEFAULTORG=`cat $CA_SUBDIR/.ca_organization`

    local C=`ask_string "Country Name (2 letter code)" "AU"`
    local ST=`ask_string "State or Province Name (full name)" "" `
    local L=`ask_string "Locality Name (eg, city)" "" `
    [[ -z "${O:-}" ]] && O=`ask_string "Organization Name (eg, company)" "$DEFAULTORG"`
    local OU=`ask_string "Organizational Unit Name (eg, section)" ""`
    local CN="$DEFAULTCN"
    [[ -z "$CN" ]] && CN=`ask_string "Common Name ($CNINFO)" "$CNHINT"`
    local emailAddress=`ask_string "Email Address" ""`
    local EMAIL=""
    [[ ! -z "$emailAddress" ]] && EMAIL="/emailAddress=$emailAddress"
    echo "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN$EMAIL"
}

function show_help() {
cat << EOF
Usage: ${0##*/} [OPTIONS] ...

    Manages client and server self-signed certificates.
    For all the commands described below, ${0##*/} must
    be called in the directory where the certificates and CA
    are stored.

${0##*/} initialize [-s KEY_SIZE] ORGANIZATION [DEFAULT-CERT-DAYS] [DEFAULT-CRL-DAYS]

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

${0##*/} create-server [-s KEY_SIZE] [-z SSL_CLIENT] DOMAIN [DAYS_VALID]

    Create a client certificate based on the current root CA. It also creates
    an example nginx configuration file ready to use (or modify).

    DOMAIN: The fully qualified domain name, eq www.example.com

    DAYS_VALID: the validity in days of the certificate
    -s KEY_SIZE: The RSA key size (default 2048)

    -z SSL_CLIENT_OPTION: (for Nginx) either "on" or "optional" (unset
    means no client ssl option is added in the nginx configuration).
    If "on", the web client is required to provide a valid
    (ie. not revoked) client certificate, or reject the https
    request (default is an http error code 400)
    If "optional", the server requests a certificate, but
    the requested content is served even if no valid certificate
    is provided (this can then be tested at the application level)


${0##*/} create-client [-s KEY_SIZE] [CLIENTNAME] [PASSWORD] [DAYS_VALID]

    Create a client certificate based on the current root CA. If CLIENTNAME,
    PASSWORD, or DAYS_VALID are not provided, they are asked for in the
    interactive console.

    CLIENTNAME: a unique name for the certificate (typically
        the name of the user of this certificate)
    PASSWORD: the password required to import this certificate.
    DAYS_VALID: the validity in days of the certificate

    -s KEY_SIZE: The RSA key size (default 2048)

${0##*/} revoke-client CERT-FOLDER

    Revoke a client certificate. The .crl.pem file, containing
    all the revoked certificated is update.
    Typically, revoking a certificate means updating the configuration
    with a fresh version of this file.

    CERT-FOLDER the path to the folder where the client certificate is stored.
       This folder is typically stored in Clients/.
       For instance ./Clients/John_Doe_20150928

${0##*/} nginx [-z SSL_CLIENT_OPTION] CERT-FOLDER

    Creates a basic nginx configuration that you can uses the
    self-signed certificate.


EOF
}

function revoke_client_certificate() {
    local NAME="${1:-}"
    local FILE=""

    [[ -f "$NAME" ]] && FILE="$NAME"
    if [[ -z "$FILE" ]] ; then
        local CLIENT_DIR=""
        [[ -d "$NAME" ]] && CLIENT_DIR="$NAME"
        if [[ -z "$CLIENT_DIR" ]] ; then
            [[ -d "./Clients/$NAME" ]] && CLIENT_DIR="./Clients/$NAME"
            [[ -d "./Clients/"`echo $NAME | tr ' ' '_'` ]] && CLIENT_DIR="./Clients/"`echo $NAME | tr ' ' '_'`
            [[ -z "$CLIENT_DIR" ]] && error_exit "No directory found in Clients/ for $NAME"
        fi
        local CERTCOUNT=`ls -1 "$CLIENT_DIR" | grep crt$ |  wc -l | xargs echo`
        [[ "$CERTCOUNT" != "1" ]] && error_exit "More than one certificate in $CLIENT_DIR ($CERTCOUNT), please specify the exact file."

        FILE="$CLIENT_DIR/"`ls -1 "$CLIENT_DIR" | grep .crt$`
    fi

    openssl ca $OPENSSL_OPTS -keyfile "$CA_FILENAME.key" -cert "$CA_FILENAME.crt"    -revoke "$FILE"
    openssl ca $OPENSSL_OPTS -keyfile "$CA_FILENAME.key" -cert "$CA_FILENAME.crt"    -gencrl -out "$CRL_FILE"

    echo =====
    echo ===== Client certificate $NAME revoked. $CRL_FILE has been updated.
    echo ===== You must update the $CRL_FILE file on the server for the revocation to take effect.
    echo =====

}

function create_client() {
    local NAME="${1:-}"
    [[ -z "$NAME" ]] && NAME=`ask_string "Name of the recipient of this certificate (eg, John Doe)" ""`
    [[ -z "$NAME" ]] && error_exit "The name must not be empty."

    local FILENAME=`echo $NAME | tr ' ' '_'`_`date "+%Y%m%d"`
    local COMMONNAME="$NAME ("`date "+%Y%m%d"`")"

    local CLIENT_DIR="./Clients/$FILENAME"
    if [[ -d "$CLIENT_DIR" ]] ; then
        fncounter=1
        while [[ -d "$CLIENT_DIR" ]]
        do
            fncounter=$(( $fncounter + 1  ))
            CLIENT_DIR="./Clients/$FILENAME"_$fncounter
        done
        COMMONNAME="$NAME ("`date "+%Y%m%d"`" v$fncounter)"
    fi

    local CLIENT_BASENAME="$CLIENT_DIR/$FILENAME"
    local CLIENT_PASSWORD="${2:-}"
    CERT_VALID_DAYS="${3:-}"

    [[ -d "$CLIENT_DIR" ]] && error_exit "Error, client $NAME already exists as $CLIENT_DIR"

    [[ -z "$ORGANIZATION" ]] && ORGANIZATION=`cat $CA_SUBDIR/.ca_organization`
    [[ "$SILENT" =~ ^[Yy]$ && -z "$SUBJECT" && ! -z "$ORGANIZATION" ]] \
        && SUBJECT="/C=/ST=/L=/O=$ORGANIZATION/OU=Client Cert. $NAME/CN=${DOMAIN_NAME:-''}"

    if [[ -z "$SUBJECT" ]]; then
        echo "Please provide information on the client certificate user"
        SUBJECT=`ask_subject "" "$ORGANIZATION" "$COMMONNAME" "the user of the certificate"`
    fi

    [[ -z "$CERT_VALID_DAYS" ]] && CERT_VALID_DAYS=`ask_string "How long, in days, will this client certificate be valid" "365"`
    [[ -z "$CLIENT_PASSWORD" ]] && CLIENT_PASSWORD=`ask_string "You must define a password for this client certificate" ""`

    echo Creating client certificate $NAME \(location $CLIENT_DIR \)

    if [ -d "$CLIENT_PASSWORD" ]; then
        echo "Error, no password set for client $NAME"
        exit 11
    fi

    mkdir -p "$CLIENT_DIR"

    echo ===== Generating the TLS client private key $CLIENT_BASENAME.key
    openssl genrsa -out "$CLIENT_BASENAME.key" "$RSA_SIZE"

    echo ===== Generating the TLS client CSR $CLIENT_BASENAME.csr
    echo "Using subject $SUBJECT"
    openssl req -nodes -new -key "$CLIENT_BASENAME.key" -out "$CLIENT_BASENAME.csr" -subj "$SUBJECT" -days "$CERT_VALID_DAYS"

    echo ===== Generating the TLS client certificate .crt
    openssl ca $OPENSSL_OPTS -keyfile "$CA_FILENAME.key" -cert "$CA_FILENAME.crt" -extensions "client_usr_cert" -notext -md sha1 -in "$CLIENT_BASENAME.csr" -out "$CLIENT_BASENAME.crt"

    openssl ca $OPENSSL_OPTS -keyfile "$CA_FILENAME.key" -cert "$CA_FILENAME.crt"  -gencrl -out "$CRL_FILE"

    echo ===== Exporting the client certificate as a pkcs12 .p12 file
    openssl pkcs12 -nodes -export -out "$CLIENT_BASENAME-FULL.pfx" -inkey "$CLIENT_BASENAME.key" -in "$CLIENT_BASENAME.crt" -certfile "$CA_FILENAME.crt" -passout "pass:$CLIENT_PASSWORD"
    cp "$CLIENT_BASENAME-FULL.pfx" "$CLIENT_BASENAME-FULL.p12"
    echo ===== Exporting the client certificate as a full-fledged PEM
    openssl pkcs12 -in "$CLIENT_BASENAME-FULL.pfx" -out "$CLIENT_BASENAME-FULL.pem" -clcerts -passin "pass:$CLIENT_PASSWORD" -passout "pass:$CLIENT_PASSWORD"
    echo "$CLIENT_PASSWORD" >"$CLIENT_BASENAME.password"

    echo =====
    echo ===== Client certificate for $NAME now available in $CLIENT_DIR/
    echo ===== Use either \"`basename $CLIENT_BASENAME-FULL.pfx`\" or \"`basename $CLIENT_BASENAME-FULL.pem`\"
    echo ===== The validity for this certificate is $CERT_VALID_DAYS days
    [[ ! -z "$CLIENT_PASSWORD" ]] && echo ===== The password to import this certificate is $CLIENT_PASSWORD
    echo ===== To revoke, use \"${0##*/} revoke-client $CLIENT_DIR\"
    echo =====

}
function create_server_certificate() {
    DOMAIN_NAME=""
    [[ ! -z "$DOMAIN" ]] && DOMAIN_NAME="$DOMAIN"
    [[ -z "$DOMAIN_NAME" && "$SILENT" =~ ^[Yy]$ ]] && error_exit "You must specify a domain name if silent mode is enabled."
    [[ -z "$DOMAIN_NAME" ]] && DOMAIN_NAME=`ask_string "Enter the domain name" ""`
    [[ -z "$DOMAIN_NAME" ]] && error_exit "You must specify a valid domain name"

    # If no domain was provided and silent mode is not enabled
    if [[ "$SILENT" =~ ^[Yy]$ && -z "$SUBJECT" ]] ; then
        DEFAULT_ORGANIZATION=
        [[ -f "$CA_SUBDIR/.ca_organization" ]] && DEFAULT_ORGANIZATION=`cat $CA_SUBDIR/.ca_organization`
        [[ -z "$ORGANIZATION" && ! -z "$DEFAULT_ORGANIZATION" ]] \
            && ORGANIZATION=${DEFAULT_ORGANIZATION:-} \
            && SUBJECT="/C=/ST=/L=/O=$ORGANIZATION/OU=Server Certificate/CN=$DOMAIN_NAME"
    fi

    [[ -z "$SUBJECT" ]] \
        && echo "Please provide the information stored in the certificate." \
        && SUBJECT=`ask_subject "$DOMAIN_NAME"`

    [[ -z "$CERT_VALID_DAYS" && "$SILENT" =~ ^[Yy]$ ]] && error_exit "You must specify on the command line how long the certificate is valid if silent mode is enabled."
    [[ -z "$CERT_VALID_DAYS" ]] && CERT_VALID_DAYS=`ask_string "How long, in days, will your certificate be valid" "365"`

    [[ "$SILENT" =~ ^[Yy]$ && -z "$SUBJECT" ]] && error_exit "When silent mode is enabled, you must specify the subject of the certificate."

    echo "Parameters:"
    [[ ! -z "$ORGANIZATION" ]] && echo " - Your organization: " ${ORGANIZATION:-}
    echo " - Your domain name: " ${DOMAIN_NAME:-}
    echo " - RSA Key size                : " $RSA_SIZE
    echo " - Validity of the certificate (in days) : " $CERT_VALID_DAYS
    [[ ! -z "$SUBJECT" ]] && echo " - Subject : " $SUBJECT

    local NOW=`date +%Y%m%d`
    local CERT_DIR="Servers/${DOMAIN_NAME}_$NOW"
    if [[ -d "$CERT_DIR" ]] ; then
        local dircounter=1
        while [[ -d "$CERT_DIR" ]]
        do
            dircounter=$(( dircounter + 1  ))
            CERT_DIR="Servers/${DOMAIN_NAME}_${NOW}_${dircounter}"
        done
    fi
    mkdir -p "$CERT_DIR"

    echo ===== Generating the certificate private key
    openssl genrsa -out "$CERT_DIR/$DOMAIN_NAME.key" $RSA_SIZE
    echo ===== Generating TLS CSR
    if [[ ! -z "$SUBJECT" ]] ; then
        openssl req -nodes -new -key "$CERT_DIR/$DOMAIN_NAME.key" -out "$CERT_DIR/$DOMAIN_NAME.csr" -subj "$SUBJECT"
    else
        openssl req -nodes -new -key "$CERT_DIR/$DOMAIN_NAME.key" -out "$CERT_DIR/$DOMAIN_NAME.csr"
    fi
    echo ===== Generating the TLS certificate based on the CA
    openssl x509 -req -in "$CERT_DIR/$DOMAIN_NAME.csr" -CA "$CA_FILENAME.crt" -CAkey "$CA_FILENAME.key" -CAcreateserial -out "$CERT_DIR/$DOMAIN_NAME".crt -days "$CERT_VALID_DAYS"
    cat "$CERT_DIR/$DOMAIN_NAME.crt" "$CA_FILENAME.crt" >"$CERT_DIR/$DOMAIN_NAME-chained-with-ca.crt"

    create_nginx_config "$DOMAIN_NAME" "$CERT_DIR"

    echo "$CERT_DIR/$DOMAIN_NAME" >$CA_SUBDIR/.last_domain_name

    echo "SRC_DOMAIN_NAME='$DOMAIN_NAME'"                           >> "$CERT_DIR/info"
    echo "SRC_CHAINED_CERT='${DOMAIN_NAME}-chained-with-ca.crt'"    >> "$CERT_DIR/info"
    echo "SRC_FILE_CERT='$DOMAIN_NAME.crt'"                         >> "$CERT_DIR/info"



    echo =====
    echo ===== The server certificate for $DOMAIN_NAME is available in "$CERT_DIR/"
    echo ===== The validity for this certificate is $CERT_VALID_DAYS days
    echo =====

}

#
# initialize_ca creates a CA structure and a root certificate in then
# current directory.
#
function initialize_ca() {
    [[ -z "$ORGANIZATION" && ! -z "${1:-}" ]] && ORGANIZATION="$1"
    [[ -z "$CERT_VALID_DAYS" && ! -z "${2:-}" ]] && CERT_VALID_DAYS="$2"
    [[ "$SILENT" =~ ^[Yy]$ ]] && [[ -z "$ORGANIZATION" ]] && error_exit "You must specify the organization to enable the silent option"
    [[ "$SILENT" =~ ^[Yy]$ && -z "$CERT_VALID_DAYS" ]] && error_exit "You must also specify the number of valid days for the certificate in order to enable the silent option"
    [[ "$SILENT" =~ ^[Yy]$ && -z "$CRL_VALID_DAYS" ]] && error_exit "You must also specify the number of valid days for the CRL in order to enable the silent option"

    [[ -d "$CA_SUBDIR" ]] && error_exit "The CA folder already exists, aborting."
    [[ -z "$ORGANIZATION" ]] && read -p "Your organization: " ORGANIZATION
    [[ -z "$ORGANIZATION" ]] && echo NO ORGANIZATION && exit 1
    [[ -z "$CERT_VALID_DAYS" ]] && CERT_VALID_DAYS=`ask_string "How long, in days, will your CA certificate be valid" "365"`

    [[ -z "$CRL_VALID_DAYS" ]] \
        && echo "The default_crl_days parameter specifies the period of time, in days" \
        && echo "before the CA shall stop working if the CRL file is not updated. This is very" \
        && echo "impacting, as it means you will need to update this file periodically at" \
        && echo "this frequency or all the client certificates will be rejected." \
        && CRL_VALID_DAYS=`ask_string "How long, in days, should you set this default crl period" "30"`

    if [[ "$SILENT" =~ ^[Yy]$ && -z "$SUBJECT" ]]
    then
        SUBJECT="/C=/ST=/L=/O=$ORGANIZATION/OU=CA/CN="
    else
        echo "Please provide some information for your root certificate."
        SUBJECT=`ask_subject "" "$ORGANIZATION" "$ORGANIZATION"`
    fi

    echo "Parameters:"
    echo " - Your organization: " $ORGANIZATION
    echo " - RSA Key size of the CA       : " $RSA_SIZE
    echo " - Validity of the CA (in days) : " $CERT_VALID_DAYS
    echo " - Validity of the CRL (in days): " $CRL_VALID_DAYS
    [[ ! -z "$SUBJECT" ]] && echo " - CA Subject: " $SUBJECT

    mkdir -p ${CA_SUBDIR}/newcerts
    mkdir -p ${CA_SUBDIR}/private
    touch ${CA_SUBDIR}/index.txt      # Index of signed certificates
    echo "01" > ${CA_SUBDIR}/serial # Next (sequential) serial number

    echo "[ current_ca ]"                       >>${CA_SUBDIR}/ca.conf
    echo "dir = " ${CA_SUBDIR}                  >>${CA_SUBDIR}/ca.conf
    echo "default_crl_days = " $CRL_VALID_DAYS  >>${CA_SUBDIR}/ca.conf
    echo 'crl = $dir/'$CRL_FILE                 >>${CA_SUBDIR}/ca.conf

#    mkdir -p ${CA_SUBDIR}/ca.db.certs   # Signed certificates storage
#    touch ${CA_SUBDIR}/ca.db.index      # Index of signed certificates
#    echo "01" > ${CA_SUBDIR}/ca.db.serial # Next (sequential) serial number
#    echo "[ current_ca ]"                       >>${CA_SUBDIR}/ca.conf
#    echo "dir = " ${CA_SUBDIR}                  >>${CA_SUBDIR}/ca.conf
#    echo "default_crl_days = " $CRL_VALID_DAYS  >>${CA_SUBDIR}/ca.conf
#    echo 'crl = $dir/'$CRL_FILE                 >>${CA_SUBDIR}/ca.conf
#certs = $dir
#new_certs_dir = $dir/ca.db.certs
#database = $dir/ca.db.index
#serial = $dir/ca.db.serial
#RANDFILE = $dir/ca.db.rand
#certificate = $dir/ca.crt
#private_key = $dir/ca.key
#default_md = sha256
#preserve = no
#policy = ca_policy
#default_days = 365


    cat  >>${CA_SUBDIR}/ca.conf<<'EOF'

database       = $dir/index.txt        # index file.
new_certs_dir  = $dir/newcerts         # new certs dir

certificate    = $dir/cacert.pem       # The CA cert
serial         = $dir/serial           # serial no file
private_key    = $dir/private/cakey.pem# CA private key
RANDFILE       = $dir/private/.rand    # random number file

default_days   = 365                   # how long to certify for
default_md     = sha256                 # md to use

policy         = ca_policy            # default policy
email_in_dn    = no                    # Don't add the email into cert DN

name_opt       = ca_default            # Subject name display option
cert_opt       = ca_default            # Certificate display option
copy_extensions = none                 # Don't copy extensions from request


[ ca_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ client_usr_cert ]
basicConstraints=CA:FALSE
nsComment = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
#extendedKeyUsage=clientAuth


EOF

    echo ===== Generating CA private key
    openssl genrsa -out $CA_FILENAME.key $RSA_SIZE
    echo ===== Generating CA certificate
    if [[ ! -z "${SUBJECT}" ]]; then
        echo "Subject: $SUBJECT"
        openssl req -nodes -x509 -new -nodes -key $CA_FILENAME.key -days $CERT_VALID_DAYS -out $CA_FILENAME.crt -subj "$SUBJECT"
    else
        openssl req -nodes -x509 -new -nodes -key $CA_FILENAME.key -days $CERT_VALID_DAYS -out $CA_FILENAME.crt
    fi

    openssl ca $OPENSSL_OPTS -keyfile $CA_FILENAME.key -cert $CA_FILENAME.crt -gencrl -out $CRL_FILE

    echo $ORGANIZATION >$CA_SUBDIR/.ca_organization

    echo =====
    echo ===== Initialization successful!
    echo ===== 'The rooCA (key and cert.) are now available. Add rootCA.crt to the'
    echo ===== "client systems to ensure they recognize any certificate created"
    echo ===== 'using this new root.'
    echo ===== 'To create a server certificate:' ${0##*/} 'create-server "your.domain.tld"'
    echo ===== 'To create a client certificate:' ${0##*/} 'create-client "John Doe"'
    echo =====
}

function create_nginx_config() {
    DOMAIN_NAME="$1"
    CERT_DIR="$2"
#    [[ -z "$DOMAIN_NAME" && -f "$CA_SUBDIR/.last_domain_name" ]] && DOMAIN_NAME=`cat $CA_SUBDIR/.last_domain_name`
#    [[ -z "$DOMAIN_NAME" ]] && error_exit 'Domain name undefined, are you in a valid CA directory?'

    SSL_CLIENT_CONFIG=""
    if [[ ! -z "$CLIENT_SSL" ]] ; then
        case "$CLIENT_SSL" in
        "on")
            SSL_CLIENT_CONFIG='  ssl_client_certificate /etc/nginx/ssl/'$CA_FILENAME'.crt;
  ssl_crl /etc/nginx/ssl/'$DOMAIN_NAME.crl.pem';
  ssl_verify_client on;'
            echo ' **** SSL client certificate is activated and mandatory'
        ;;
        "optional")
            SSL_CLIENT_CONFIG='  ssl_client_certificate /etc/nginx/ssl/'$CA_FILENAME'.crt;
  ssl_crl /etc/nginx/ssl/'$CRL_FILE';
  ssl_verify_client optional;'
            echo ' **** SSL client certificate is activated but optional'
        ;;
        *)
            error_exit "Invalid ssl_verify_client value"
            ;;
        esac
    fi

    mkdir -p "$CERT_DIR/nginx"
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
' >"$CERT_DIR/nginx/$DOMAIN_NAME"
}

OPTIND=1 # Reset is necessary if getopts was used previously in the script.  It is a good idea to make this local in a function.
while getopts ":ho:d:r:s:z:g:yf:" opt; do
    case "$opt" in
        h) show_help ; normal_exit
           ;;
        $OPT_ORGANIZATION) ORGANIZATION=$OPTARG
           ;;
        $OPT_DOMAIN) DOMAIN=$OPTARG
           ;;
        $OPT_CERT_VALID_DAYS) CERT_VALID_DAYS=$OPTARG
           ;;
        $OPT_CRL_VALID_DAYS) CRL_VALID_DAYS=$OPTARG
           ;;
        $OPT_RSA_SIZE) RSA_SIZE=$OPTARG
           ;;
        $OPT_CLIENT_SSL) CLIENT_SSL=$OPTARG
           ;;
        $OPT_SILENT) SILENT=Y
           ;;
        $OPT_SUBJECT) SUBJECT=$OPTARG
            ;;
        '?')
            error_exit "Unknown option $OPTARG"
            ;;
    esac
done
shift "$((OPTIND-1))" # Shift off the options and optional --.

if [[ -z "${1:-}" ]] ; then
    error_exit "You must specify a command (initialize, create-domain, create-client, revoke-client)."
fi

case "${1:-}" in
    "initialize")
        [[ ! -z "${2:-}" ]] && ORGANIZATION="${2}"
        [[ ! -z "${3:-}" ]] && CERT_VALID_DAYS="${3}"
        [[ ! -z "${4:-}" ]] && CRL_VALID_DAYS="${4}"
        [[ -z "${CRL_VALID_DAYS}" && ! -z "${CERT_VALID_DAYS}" ]] && CRL_VALID_DAYS="${CERT_VALID_DAYS}"
        initialize_ca "${2:-}"
        ;;
    "create-server")
        [[ ! -z "${2:-}" ]] && DOMAIN="${2}"
        [[ ! -z "${3:-}" ]] && CERT_VALID_DAYS="${3}"
        create_server_certificate
        ;;
    "create-client")
        create_client "${2:-}" "${3:-}" "${4:-}"
        ;;
    "revoke-client")
        revoke_client_certificate "${2:-}"
        ;;
    "nginx")
        create_nginx_config "${2:-}"
        ;;
    *)
        error_exit "Unknown command ${1:-}"
        ;;
esac

trap - EXIT