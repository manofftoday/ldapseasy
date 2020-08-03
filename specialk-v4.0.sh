#!/bin/bash
########################################################################
#Script Name	: SPECIALK
#Description	: OpenLDAP + Kerberos Deployment Script for SLES12 SP3
#Args           :
#Author       	: Dari Garcia (manofftoday)
#GitHub         : https://github.com/manofftoday
#Version        : 2.0
########################################################################
#FUNDAMENTAL VARIABLES
########################################################################
# This environment sets an exit when any command fails
set -e
temporaldir=/tmp/specialk
SRVNAME=authsrv1.cgg1.skmf.com
BASEDN=dc=cgg1,dc=skmf,dc=com
TLSPATH=/certs
TLSCA=/certs/authsrv1.cgg1.skmf.com.pem
TLSSERVER=/certs/authsrv1.cgg1.skmf.com.pem
TLSKEY=/certs/authsrv1.cgg1.skmf.com.key.pem
BINDDN=cn=Administrator,dc=cgg1,dc=skmf,dc=com
CNBIND=Administrator
KRBREALM=CGG1.SKMF.COM
DOMNAME=cgg1.skmf.com
KDCIP=authsrv1.cgg1.skmf.com
KDC2IP=authsrv2.cgg1.skmf.com
KADMIP=authsrv1.cgg1.skmf.com
LDAPURI=ldap://authsrv1.cgg1.skmf.com
LDAP2URI=ldap://authsrv2.cgg1.skmf.com
DOM1=cgg1
# This environment sets the temporal directory location
##########################################
##########################################
##########################################
#      ENVIRONMENTS - NON-INTERACTIVE    #
##########################################
#Uncomment the environments if you select#
#  not to enable interactive mode and    #
#   hardcode the correct values for      #
#          your environment              #
##########################################
#SRVNAME: FQDN OF SERVER WHERE THE SCRIPT IS GOING TO DEPLOY THE CONFIGURATION
#SRVNAME=provider.ex.ample.com
#
#LDAP DOMAIN BASE DISTINGUISHED NAME
#BASEDN=dc=ex,dc=ample,dc=com
#
#SSL CERTIFICATES ABSOLUTE LOCAL PATH
#TLSPATH=/certs
#
#SSL CA CERTIFICATE ABSOLUTE LOCAL PATH IN PEM FORMAT
#TLSCA=/certs/provider.ex.ample.com.pem
#
#SSL SERVER CERTIFICATE ABSOLUTE LOCAL PATH IN PEM FORMAT
#TLSSERVER=/certs/provider.ex.ample.com.pem
#
#SSL SERVER CERTIFICATE KEY ABSOLUTE LOCAL PATH IN PEM FORMAT UNENCRYPTED
#TLSKEY=/certs/provider.ex.ample.com.key.pem
#
#LDAP BIND DN AUTHENTICATION USER DISTINGUISHED NAME
#BINDDN=cn=Administrator,dc=ex,dc=ample,dc=com
#
#COMMON NAME FOR AUTHENTICATION BIND DN LDAP USER
#CNBIND=Administrator
#
#KERBEROS REALM
#KRBREALM=EX.AMPLE.COM
#
#DOMAIN NAME
#DOMNAME=ex.ample.com
#
#MASTER KDC SERVER IP. FOR STANDALONE INITIAL CONFIGURATION USE THE SERVER FQDN TO CONFIGURE
#KDCIP=provider.ex.ample.com
#
#SLAVE KDC SERVER IP. FOR STANDALONE INITIAL CONFIGURATION USE THE SERVER FQDN TO CONFIGURE
#KDC2IP=consumer.ex.ample.com
#
#ADMINISTRATION KRB5 SERVER IP. FOR STANDALONE INITIAL CONFIGURATION USE THE SERVER FQDN TO CONFIGURE
#KADMIP=provider.ex.ample.com
#
#LDAP MASTER URI. FOR STANDALONE INITIAL CONFIGURATION USE THE SERVER FQDN TO CONFIGURE
#LDAPURI=ldap://provider.ex.ample.com
#
#LDAP SLAVE URI. FOR STANDALONE INITIAL CONFIGURATION USE THE SERVER FQDN TO CONFIGURE
#LDAP2URI=ldap://consumer.ex.ample.com
#
#FIRST PART OF BASEDN
#DOM1=ex
#

#############################
#############################
#############################
#############################
##########################################
#                FUNCTIONS              #
##########################################
#############################
#############################
#############################
#############################
#############################
#############################
#############################
#############################
#********************#
#       GENERAL FUNCTIONS #
#********************#
#############################
#############################
#############################
#############################
#############################
#############################
#############################
#############################
#MAIN MENU FUNCTION
#############################
function main_menu(){
  clear
  cat <<'EOF'
 __   ___   ____  __    _    __    _     _
( (` | |_) | |_  / /`  | |  / /\  | |   | |_/
_)_) |_|   |_|__ \_\_, |_| /_/--\ |_|__ |_| \

SPECIALK: v3.1 - 29/07/2020

EOF
  sleep 1
  A='Welcome to SPECIALK. Please enter your choice using the number keys: '
  echo $A
  options=("New Auth Server" \
  "SYNCREPL - Configure this server as LDAP Provider" \
  "SYNCREPL - Configure this server as LDAP Consumer" \
  "SYNCREPL SASL - Configure this server as LDAP Consumer" \
  "SASLAUTHD - Enable Passthrough" \
  "PAM - Re-Configure PAM Service" \
  "SSSD - Re-Configure Logon Management" \
  "LDAP - Add group to LDAP SUDOers" \
  "SSH - Enable GSSAPI SSH" \
  "KRB5 - Remote Configure - Kerberos Replication" \
  "Purge Temporal Files" \
  "Uninstall" \
  "Quit")
  select opt in "${options[@]}"
  do
    case $opt in
            "New Auth Server")
                    clear
                    new_srv;
                    break
            ;;
            "SYNCREPL - Configure this server as LDAP Provider")
                    clear
                    enable_syncprovider;
                    break
            ;;
            "SYNCREPL - Configure this server as LDAP Consumer")
                    clear
                    enable_syncconsumer;
                    break
            ;;
            "SYNCREPL SASL - Configure this server as LDAP Consumer" )
                    clear
                    enable_syncconsumersasl;
                    break
            ;;
            "SASLAUTHD - Enable Passthrough")
                    clear
                    configure_saslauthd;
                    break
            ;;
            "PAM - Re-Configure PAM Service")
                    clear
                    reconf_pam;
                    break
            ;;
            "SSSD - Re-Configure Logon Management")
                    clear
                    conf_logon;
                    break
            ;;
            "LDAP - Add group to LDAP SUDOers")
                    clear
                    sudoers_add;
                    break
            ;;
            "SSH - Enable GSSAPI SSH")
                    clear
                    krb5_ssh_gen;
                    break
            ;;
            "KRB5 - Remote Configure - Kerberos Replication")
                    clear
                    new_slavekdc;
                    break
            ;;
            "Purge Temporal Files")
                    clear
                    purge_files;
                    break
            ;;
            "Uninstall")
                    clear
                    uninstall;
                    break
            ;;
            "Quit")
            break
            ;;
          *) echo "invalid option $REPLY";;
      esac
  done
}
#############################
#ROOT CHECKER
#############################
function root_chck(){
  if ! [ $(id -u) = 0 ]; then
    echo "You must be root in order to run this application. Exiting..."
    exit 1
    fi
  clear
}
#############################
#GATHERING INFORMATION FUNCTION
#############################
function intquest(){
  clear
  read -p "Please, provide the Server FQDN where this script is being installed: " SRVNAME
  read -p "Please provide the domain name: " DOMNAME
  read -p "Please provide the base name, e.g dc=domain,dc=com: " BASEDN
  read -p "Please provide the Master LDAP URI, e.g ldap://127.0.0.1:389. If you are deploying a standalone auth server, use the LDAP URI of the server to configure: " LDAPURI
  read -p "Please provide the LDAP certificates path, eg /etc/openldap/certs: " TLSPATH
  read -p "Please provide the TLS CACert path and file name: " TLSCA
  read -p "Please provide the TLS Server Certificate path and filename: " TLSSERVER
  read -p "Please provide the TLS Server Key path and filename: " TLSKEY
  read -p "Please provide the Bind DN: " BINDDN
  read -p "Please provide the CN Bind DN: " CNBIND
  read -p "Please provide the REALM NAME: " KRBREALM
  read -p "Please provide the KDC Master IP or hostname. If you are deploying a standalone auth server, use the FQDN of the server to configure: " KDCIP
  read -p "Please provide the Kerberos Administration Server IP or hostname: " KADMIP
  read -p "Please provide the first part of BASEDN, e.g domain: " DOM1

}
#############################################
#INTERACTIVE MODE + CHECKER FUNCTION:
#############################################
function ask_info(){
  clear
  intquest;
  sleep 1
  clear
  echo "FQDN AUTH SERVER: $SRVNAME"
  echo "DOMAIN NAME: $DOMNAME"
  echo "BASE DN: $BASEDN"
  echo "LDAP-URI: $LDAPURI"
  echo "CERTIFICATES PATH: $TLSPATH"
  echo "SERVER CERTIFICATE: $TLSSERVER"
  echo "CA CERTIFICATE: $TLSCA"
  echo "KEY CERTIFICATE: $TLSKEY"
  echo "BIND DN: $BINDDN"
  echo "KERBEROS REALM: $KRBREALM"
  echo "KDC MASTER IP: $KDCIP"
  echo "ADM MASTER IP: $KADMIP"
  echo "BASEDN FIRST PART: $DOM1"
  echo "SECONDARY KDC SERVER: $KDC2IP"
  echo "SECONDARY LDAP SERVER: $LDAP2URI"
  read -p "Is the information correct? [y/n]:" a
  if [ "$a" != "y" ]
    then
      ask_info;
  fi
    }
#############################
# INTERACTIVE MODE FUNCTION
#############################
function interactive_mode(){
  #reading information - interactive mode
  echo "Would you like to use interactive mode?"
  echo "Please keep in mind that if you select no, you will have to hardcode the environments"
  select yn in "Yes" "No"; do
  case $yn in
    Yes ) ask_info; break;;
    No ) break;;
  esac
  done
}
#############################
#############################
#############################
#############################
#############################
#############################
#*****************************
# INSTALL PACKAGES FUNCTIONS #
#*****************************
#############################
#############################
#############################
#############################
#############################
#############################
#############################
# INSTALL SERVER PACKAGES (ZYPPER)
#############################
function zypper_pack_srv(){
  echo "You will need an internet connection with active SUSE subscription to official repositories. Otherwise insert DVD/CD"
  echo "Would you like to continue?[y/n]"
  read a
  if [ "$a" = "y" ]
  then
    echo "Installing SERVER packages. Please wait..."
    zypper refresh
    zypper in -y openldap2 openldap2-client krb5-server krb5-client krb5-appl-clients\
    krb5-appl-servers krb5-plugin-kdb-ldap libndr-krb5pac0 acl libndr-krb5pac0-32bit\
    krb5-plugin-kdb-ldap pam_krb5 cyrus-sasl-gssapi
    echo "All packages has been installed."
  else
    break
fi
echo "You will need an eliptic curve certificate generation in order to make this setup work".
echo "Would you like to generate it now?[y/n]"
read a
if [ "$a" = "y" ]
then
  openssl dhparam -out /certs/dhparam-2048.pem 2048
else
  break
fi
}
###################################
# INSTALL CLIENT PACKAGES (ZYPPER)
###################################
function zypper_pack_cli(){
  echo "You will need an internet connection with active SUSE subscription to official repositories. Otherwise insert DVD/CD"
  echo "Would you like to continue?[y/n]"
  read a
  if [ "$a" = "y" ]
  then
  echo "Installing CLIENT packages. Please wait..."
  zypper refresh
  zypper in -y libldap-2_4-2 libldap-2_4-2-32bit libldapcpp1 libsmbldap0\
  libsmbldap0-32bit nss_ldap nss_ldap-32bit openldap2-client acl sssd-ldap\
  yast2-ldap krb5 krb5-32bit krb5-appl-clients krb5-appl-servers krb5-client\
  libndr-krb5pac0 libndr-krb5pac0-32bit pam_krb5 pam_ldap pam_ldap-32bit\
  pam_krb5-32bit cyrus-sasl-gssapi nss_ldap nss_ldap-32bit nscd
  echo "All packages has been installed."
  else
    break
  fi
}
function uninstall(){
  echo "The LDAP deployment will be totally removed."
  echo "Would you like to continue?[y/n]"
  read a
  if [ "$a" = "y" ]
  then
  echo "Uninstalling packages. Please wait..."
  zypper remove openldap2-client krb5 krb5-32bit krb5-appl-clients krb5-appl-servers krb5-client\
  openldap2 krb5-server krb5-plugin-kdb-ldap krb5-plugin-kdb-ldap
  echo "All packages has been uninstalled."
  echo "Removing data"
  rm -rf /etc/ldap.conf
  rm -rf /etc/openldap
  rm -rf /var/lib/ldap
  rm -rf /etc/krb5.keytab
  rm -rf /var/lib/kerberos
  rm -rf /etc/krb5.conf
  else
    break
  fi
}
#############################
#############################
#############################
#############################
#############################
#############################
#***************************#
#     OPENLDAP FUNCTIONS    #
#***************************#
#############################
#############################
#############################
#############################
#############################
#############################
#DAEMON CONFIGURATOR
#This function configures the
#LDAP SERVICE DAEMON options
#with systemd
#############################
function ldap_service_conf(){
echo "Setting up the OpenLDAP Service..."
cat <<EOF > /etc/sysconfig/openldap
OPENLDAP_START_LDAP="yes"
OPENLDAP_START_LDAPS="no"
OPENLDAP_START_LDAPI="yes"
OPENLDAP_SLAPD_PARAMS=""
OPENLDAP_USER="ldap"
OPENLDAP_GROUP="ldap"
OPENLDAP_CHOWN_DIRS="yes"
OPENLDAP_LDAP_INTERFACES=""
OPENLDAP_LDAPS_INTERFACES=""
OPENLDAP_LDAPI_INTERFACES=""
OPENLDAP_REGISTER_SLP="yes"
OPENLDAP_KRB5_KEYTAB="/etc/ldap.keytab"
OPENLDAP_CONFIG_BACKEND="ldap"
OPENLDAP_MEMORY_LIMIT="yes"
EOF
}
#############################
#SLAPD CONFIGURATOR
#This function configures the slapd
#initial configuration and deploy the
#config database
#############################
function slapd_gen(){
  mv /etc/openldap/slapd.conf /etc/openldap/slapd.conf.orig
  touch /etc/openldap/slapd.conf
  rm -rf /etc/openldap/slapd.d/*
  slaptest -f /etc/openldap/slapd.conf -F /etc/openldap/slapd.d
  cp /etc/openldap/slapd.d/cn=config/olcDatabase\={0}config.ldif /etc/openldap/slapd.d/cn=config/olcDatabase\={0}config.ldif.orig
  cat <<EOF > /etc/openldap/slapd.d/cn=config/olcDatabase\={0}config.ldif
dn: olcDatabase={0}config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break
olcAddContentAcl: TRUE
olcLastMod: TRUE
olcMaxDerefDepth: 15
olcReadOnly: FALSE
olcRootDN: cn=config
olcSyncUseSubentry: FALSE
olcMonitoring: FALSE
structuralObjectClass: olcDatabaseConfig
entryUUID: 68923b7e-cbb9-1039-9c6c-f17d4b6cc6de
creatorsName: cn=config
createTimestamp: 20200115080433Z
entryCSN: 20200115080433.129231Z#000000#000#000000
modifiersName: cn=config
modifyTimestamp: 20200115080433Z
EOF
  echo "Changing owner and permissions for /etc/openldap/slap.d Please wait..."
  chown -R ldap. /etc/openldap/slapd.d
  chmod -R 700 /etc/openldap/slapd.d
  cat <<EOF > /etc/openldap/slapd.conf
access to *
        by * read
EOF
  echo "starting openldap, Please wait..."
  systemctl start slapd
  echo "Enabling onboot openldap, Please wait..."
  systemctl enable slapd
  echo "slapd.d created!"
}

##########################################################
#CHROOTPW GENERATOR
#This function asks for a Password
#which converts to SSHA with salt required
#and use it to upload it as RootPW to the Database
#Also creates the ldap-pw password service file
##########################################################
function ldap_pw_gen(){
  echo "Generating new ciphered password. Please enter the Authentication Server Management password"
  read -p "New Password" -s p
  slappasswd
  echo "Applying changes..."
  PASS=$(slappasswd -h {SSHA} -s $p)
  cat <<EOF > $temporaldir/chrootpw.ldif
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: $PASS
EOF
  echo "Importing chrootpw.ldif"
  ldapadd -Y EXTERNAL -H ldapi:/// -f $temporaldir/chrootpw.ldif
  echo "chrootpw.ldif added!"
  echo "Creating ldap-pw service password file in /etc/openldap/ldap-pw..."
  cat << EOF > /etc/openldap/ldap-pw
$BINDDN#$PASS

EOF
}

#####################################################################
#SCHEMAS IMPORT
#This function imports the required schemas to the LDAP Database
#Please remind that schema files should be located in the path provided
#####################################################################
function schema_import(){
  echo "Importing schemas..."
  mkdir -p $temporaldir/schemas.d/
  cat > $temporaldir/schemas.d/schema_conv.conf << EOL
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/sudo.schema
include /etc/openldap/schema/ppolicy.schema
include /etc/openldap/schema/dnszone.schema
include /etc/openldap/schema/dlz.schema
include /etc/openldap/schema/ldapns.schema
include /etc/openldap/schema/rfc2307bis.schema
include /etc/openldap/schema/yast.schema
include /etc/openldap/schema/inetorgperson.schema
include /usr/share/doc/packages/krb5/kerberos.schema
EOL
  mkdir $temporaldir/schemas.d/ldif_output/
  slapcat -f $temporaldir/schemas.d/schema_conv.conf -F $temporaldir/schemas.d/ldif_output/ \
  -n0 -s "cn={12}kerberos,cn=schema,cn=config" > $temporaldir/cn=kerberos.ldif
  #Replacing Kerberos DN
  sed -i 's/dn: cn=kerberos,cn=schema,cn=config/cn=kerberos/g'  $temporaldir/cn\=kerberos.ldif
  slaptest -f $temporaldir/schemas.d/schema_conv.conf -F $temporaldir/schemas.d
  #Adding to the database
  sudo ldapadd -Q -Y EXTERNAL -H ldapi:/// -f $temporaldir/cn\=kerberos.ldif
  #Copying Schema files configured to Ldap File System
  mkdir -p /etc/openldap/slapd.d/cn\=config/cn\=schema/
  cp $temporaldir/schemas.d/cn\=config/cn\=schema/* /etc/openldap/slapd.d/cn\=config/cn\=schema/
  #Changing permissions to ldap
  chown ldap. /etc/openldap/slapd.d/cn\=config/cn\=schema/*.ldif
  systemctl restart slapd
  echo "schemas imported succesfully!"
}
#########################################
#BACKEND.LDIF GENERATOR FUNCTION
#This function configures the Backend file to be uploaded to the database
#Also the required ACLs- WARNING - WITHOUT THESE ACL's SSSD ID Provider WON'T WORK
########################################
function backend_gen(){
cat <<EOF > $temporaldir/backend.ldif
#Load dynamic backend modules
dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
#olcModulepath: /usr/lib/openldap
olcModuleload: back_hdb.la

dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModulepath: /usr/lib/openldap/modules
olcModuleload: refint.la

dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModulepath: /usr/lib/openldap/modules
olcModuleload: memberof.la

# Database settings
dn: olcDatabase=hdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcHdbConfig
olcDatabase: {1}hdb
olcSuffix: $BASEDN
olcDbDirectory: /var/lib/ldap
olcRootDN: $BINDDN
olcRootPW: $PASS
olcDbConfig: set_cachesize 0 2097152 0
olcDbConfig: set_lk_max_objects 1500
olcDbConfig: set_lk_max_locks 1500
olcDbConfig: set_lk_max_lockers 1500
olcDbIndex: objectClass eq
olcDbIndex: cn pres,sub,eq
olcDbIndex: sn pres,sub,eq
olcDbIndex: uid pres,sub,eq
olcDbIndex: displayName pres,sub,eq
olcDbIndex: default sub
olcDbIndex: uidNumber eq
olcDbIndex: gidNumber eq
olcDbIndex: mail,givenName eq,subinitial
olcDbIndex: dc eq
olcDbIndex: krbPrincipalName
olcLastMod: TRUE
olcDbCheckpoint: 512 30
olcAccess: to * by * write
EOF
    ldapadd -Y EXTERNAL -H ldapi:/// -f $temporaldir/backend.ldif
    echo "backend.ldif imported!"
}
#########################################
#FRONTEND ACL GENERATOR FUNCTION
#This function configures the ACL's required for the Frontend database
########################################
function frontendacl(){
  echo "Adding frontend ACL's..."
  cat <<EOF > $temporaldir/frontendacl.ldif
dn: olcDatabase={-1}frontend,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to dn.base="cn=subschema"  by * read
olcAccess: {1}to dn.base="" by * read
EOF
ldapmodify -Y EXTERNAL -H ldapi:/// -f $temporaldir/frontendacl.ldif
}

function ldapaclroot(){
  echo "Adding domain ACL's..."
  cat  <<EOF > $temporaldir/ldapacl.ldif
dn: olcDatabase={1}hdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: to dn.base=""
  by * read
olcAccess: to dn.base="cn=Subschema"
  by dn.base="uid=syncrepl,cn=$KRBREALM,cn=gssapi,cn=auth" read
  by * read
olcAccess: to dn.subtree="ou=People,$BASEDN"
  by dn.base="uid=syncrepl,cn=$KRBREALM,cn=gssapi,cn=auth" read
  by dn.exact="uid=kdc-service,ou=Services,$BASEDN" write
  by dn.exact="uid=adm-service,ou=Services,$BASEDN" write
  by * read
olcAccess: to dn.subtree="ou=Group,$BASEDN"
  by dn.base="uid=syncrepl,cn=$KRBREALM,cn=gssapi,cn=auth" read
  by * read
olcAccess: to dn.subtree="ou=ldapconfig,$BASEDN"
  by dn.base="uid=syncrepl,cn=$KRBREALM,cn=gssapi,cn=auth" read
  by * none
olcAccess: to dn.subtree="ou=SUDOers,$BASEDN"
  by dn.base="uid=syncrepl,cn=$KRBREALM,cn=gssapi,cn=auth" read
  by * none
olcAccess: to dn.subtree="cn=$KRBREALM,cn=krbContainer,$BASEDN"
  by dn.exact="uid=kdc-service,ou=Services,$BASEDN" write
  by dn.exact="uid=adm-service,ou=Services,$BASEDN" write
  by dn.base="uid=syncrepl,cn=$KRBREALM,cn=gssapi,cn=auth" read
  by * none
olcAccess: to attrs=userPassword
  by dn.base="uid=syncrepl,cn=$KRBREALM,cn=gssapi,cn=auth" read
  by self write
  by * auth
olcAccess: to attrs=shadowLastChange
  by dn.base="uid=syncrepl,cn=$KRBREALM,cn=gssapi,cn=auth" read
  by self write
  by * read
olcAccess: to *
  by * read
EOF
ldapmodify -Y EXTERNAL -H ldapi:/// -f $temporaldir/ldapacl.ldif

}
#########################################
#BASEDOMAIN GENERATOR FUNCTION
#This function configures the basedomain and all the structure of the Directory
########################################
function basedomain_gen(){
  echo "Importing basedomain.ldif... Please Wait..."
  cat <<EOF > $temporaldir/basedomain.ldif
dn: $BASEDN
objectClass: top
objectClass: dcObject
objectclass: organization
o: $DOMNAME
dc: $DOM1

dn: $BINDDN
objectClass: organizationalRole
cn: $CNBIND
description: Directory Manager

dn: ou=People,$BASEDN
objectClass: organizationalUnit
ou: People

dn: ou=Group,$BASEDN
objectClass: organizationalUnit
ou: Group

dn: ou=ldapconfig,$BASEDN
objectClass: organizationalUnit
objectClass: top
ou: ldapconfig

dn: cn=groupconfiguration,ou=ldapconfig,$BASEDN
objectClass: suseGroupConfiguration
objectClass: suseModuleConfiguration
objectClass: top
cn: groupconfiguration
suseDefaultBase: ou=group,$BASEDN
suseDefaultTemplate: cn=grouptemplate,ou=ldapconfig,$BASEDN
suseMaxUniqueId: 60000
suseMinUniqueId: 10000
suseNextUniqueId: 10001
suseSearchFilter: objectClass=posixGroup

dn: cn=grouptemplate,ou=ldapconfig,$BASEDN
objectClass: suseGroupTemplate
objectClass: suseObjectTemplate
objectClass: top
cn: grouptemplate
suseNamingAttribute: cn
susePlugin: UsersPluginLDAPAll

dn: cn=userconfiguration,ou=ldapconfig,$BASEDN
objectClass: suseUserConfiguration
objectClass: suseModuleConfiguration
objectClass: top
cn: userconfiguration
suseDefaultBase: ou=people,$BASEDN
suseDefaultTemplate: cn=usertemplate,ou=ldapconfig,$BASEDN
suseMaxPasswordLength: 8
suseMaxUniqueId: 60000
suseMinPasswordLength: 5
suseMinUniqueId: 10000
suseNextUniqueId: 10001
susePasswordHash: SSHA
suseSearchFilter: objectClass=posixAccount
suseSkelDir: /etc/skel

dn: cn=usertemplate,ou=ldapconfig,$BASEDN
objectClass: suseUserTemplate
objectClass: suseObjectTemplate
objectClass: top
cn: usertemplate
suseDefaultValue: homeDirectory=/home/%uid
suseDefaultValue: loginShell=/bin/bash
suseNamingAttribute: uid
susePlugin: UsersPluginLDAPAll
susePlugin: UsersPluginKerberos

dn: ou=SUDOers,$BASEDN
objectClass: organizationalUnit
ou: SUDOers

dn: ou=Services,$BASEDN
objectClass: organizationalUnit
ou: Services

dn: cn=Services,ou=Group,$BASEDN
objectClass: top
objectClass: posixGroup
objectClass: groupOfNames
gidNumber: 20000
member: uid=adm-service,ou=Services,$BASEDN
member: uid=kdc-service,ou=Services,$BASEDN
member: uid=lam,ou=Services,$BASEDN
member: uid=syncrepl,ou=Services,$BASEDN

dn: uid=lam-service,ou=Services,$BASEDN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
cn: lam-service
gidNumber: 20000
homeDirectory: /dev/null
sn: lam-service
uid: lam-service
uidNumber: 30000
businessCategory: Service
givenName: Service
loginShell: /bin/false
userPassword: $PASS

dn: uid=adm-service,ou=Services,$BASEDN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
cn: adm-service
gidNumber: 20000
homeDirectory: /dev/null
sn: adm-service
uid: adm-service
uidNumber: 30001
businessCategory: Service
givenName: Service
loginShell: /bin/false
userPassword: $PASS

dn: uid=kdc-service,ou=Services,$BASEDN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
cn: kdc-service
gidNumber: 20000
homeDirectory: /dev/null
sn: kdc-service
uid: kdc-service
uidNumber: 30002
businessCategory: Service
givenName: Service
loginShell: /bin/false
userPassword: $PASS

dn: cn=defaults,ou=SUDOers,$BASEDN
objectClass: sudoRole
objectClass: top
cn: defaults
description: Default options
sudoOption: env_keep+=SSH_AUTH_SOCK

dn: cn=%Administrators,ou=SUDOers,$BASEDN
objectClass: sudoRole
objectClass: top
cn: %Administrators
sudoCommand: ALL
sudoHost: ALL
sudoUser: %Administrators

dn: uid=searchuser,ou=Services,$BASEDN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
cn: searchuser
gidNumber: 20000
homeDirectory: /dev/null
sn: searchuser
uid: searchuser
uidNumber: 30003
businessCategory: Service
givenName: Service
loginShell: /bin/false
userPassword: secret
EOF
  echo "Importing basedomain..."
  ldapadd -D $BINDDN -W -H ldapi:/// -f  $temporaldir/basedomain.ldif
  echo "basedomain.ldif imported!"
}

#########################################
#LDAP SSL MOD CONFIGURATION
#This function enables and configure the ldap mod_ssl
########################################
function ssl_ldap_gen(){
  echo "Importing ssl configuration to directory... Please Wait..."
  cat <<EOF > $temporaldir/mod_ssl.ldif
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: $TLSCA
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: $TLSKEY
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: $TLSSERVER
EOF
  chown -R ldap:ldap $TLSPATH
  setfacl -m u:ldap:r-x $TLSPATH
  setfacl -m u:ldap:r-x $TLSCA
  setfacl -m u:ldap:r-x $TLSKEY
  setfacl -m u:ldap:r-x $TLSSERVER
  chmod -R 777 /certs
  ldapmodify -Y EXTERNAL -H ldapi:/// -f $temporaldir/mod_ssl.ldif
  echo "mod_ssl.ldif imported!"
}

function harden_objects(){
  echo "Importing cyphering configuration to directory... Please Wait..."
  cat <<EOF > $temporaldir/ciphering.ldif
dn: cn=config
changetype: modify
add: olcDisallows
olcDisallows: bind_anon
-
replace: olcRequires
olcRequires: authc
EOF
ldapmodify -Y EXTERNAL -H ldapi:/// -f $temporaldir/ciphering.ldif

}

#############################
#############################
#############################
#############################
#############################
#############################
# LDAP HA FUNCTIONS
#############################
#############################
#############################
#############################
#############################
#############################
#LDAP REPLICATION PROVIDER
#This function configures the server where is executed as provider in SyncRepl
#############################
function provider(){
  cat <<EOF >  $temporaldir/mod_syncprov.ldif
dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModuleLoad: syncprov.la
EOF
  ldapadd -Y EXTERNAL -H ldapi:/// -f $temporaldir/mod_syncprov.ldif
  echo "syncprov.la module enabled"
  cat <<EOF >  $temporaldir/syncprov.ldif
dn: olcOverlay=syncprov,olcDatabase={1}hdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcSyncProvConfig
olcOverlay: syncprov
olcSpSessionLog: 100
EOF
  ldapadd -Y EXTERNAL -H ldapi:/// -f  $temporaldir/syncprov.ldif
  echo "This server has been configured as a Provider in a Syncrepl environment"
  sleep 2
main_menu;
}
#############################
#LDAP REPLICATION CONSUMER
#This function configures the server where is executed as consumer in SyncRepl
#This function will erase the existing database.
#A standalone authentication server should have been already deployed before.
#############################
#BIND SIMPLE AUTHENTICATION CONSUMER SYNCREPL
function consumer(){
  read -p "Enter replication id (default=001): " RID
  read -p "Enter replication provider ldap URI: " PROVURI
  read -p "Enter the BIND DN: " BINDDN
  read -p "Enter the BIND DN password: " -s p
  BINDPASS=$(slappasswd -h {SSHA} -s $p)
  echo "\n"
  read -p "Enter the search BASEDN e.g dc=domain,dc=com (Between quotation marks): " BASEDN
  cat <<EOF > $temporaldir/syncrepl.ldif
dn: olcDatabase={1}hdb,cn=config
changetype: modify
add: olcSyncRepl
olcSyncRepl: rid=$RID
  provider=$PROVURI
  bindmethod=simple
  binddn=$BINDDN
  credentials=$BINDPASS
  searchbase=$BASEDN
  scope=sub
  schemachecking=on
  type=refreshAndPersist
  retry="30 5 300 3"
  interval=00:00:05:00
EOF
  echo "This server has been configured as a Consumer of $PROVURI"
  echo "Erasing temporal files..."
  ldapadd -Y EXTERNAL -H ldapi:/// -f $temporaldir/syncrepl.ldif
  echo "Erasing old database..."
  rm -rf /var/lib/ldap/*
  echo "Restarting slapd service..."
  systemctl restart slapd
  echo "Success"
}

#GSSAPI SASL CONSUMER SYNCREPL
function consumersasl(){
  read -p "Please, keep in mind that you will need root ssh access on Provider and Consumer to perform this operation. Would you like to continue? (y/n)" a
  if [ "$a" = "y" ]
    then
  read -p "Enter replication id (default=001): " RID
  read -p "Enter the search BASEDN e.g dc=domain,dc=com: " BASEDN
  read -p "Enter the REALM: " KRBREALM
  read -p "Provider FQDN: " PROVFQDN
  read -p "Consumer FQDN: " CONSFQDN
  read -p "Enter the BINDDN: " BINDDN
  echo "Creating the syncrepl.ldif"
  cat <<EOF > $temporaldir/syncrepl.ldif
dn: olcDatabase={1}hdb,cn=config
changetype: modify
add: olcSyncRepl
olcSyncRepl: rid=$RID
  provider=ldap://$PROVFQDN
  sizelimit=unlimited
  bindmethod=sasl
  saslmech=gssapi
  searchbase="$BASEDN"
  scope=sub
  schemachecking=on
  type=refreshAndPersist
  retry="30 5 300 3"
  interval=00:00:05:00
  authcid="syncrepl/$CONSFQDN@$KRBREALM"
EOF
  ldapadd -Y EXTERNAL -H ldapi:/// -f $temporaldir/syncrepl.ldif
  echo "olcSyncRepl added"
  sleep 1
  echo "Adding syncrepl uid to ldap"
  cat <<EOF > $temporaldir/syncuid.ldif
dn: uid=syncrepl/$CONSFQDN,ou=Services,$BASEDN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
cn: syncrepl/$CONSFQDN
gidNumber: 20000
homeDirectory: /dev/null
sn: syncrepl/$CONSFQDN
uid: syncrepl/$CONSFQDN
uidNumber: 30003
businessCategory: Service
givenName: Service
loginShell: /bin/false
userPassword: {SASL}syncrepl/$CONSFQDN@$KRBREALM
EOF
  ldapadd -D $BINDDN -W -H ldap://$PROVFQDN/ -f  $temporaldir/syncuid.ldif
  echo "Updating /etc/sysconfig/openldap..."
  sed -i 's/OPENLDAP_USER="ldap"/"OPENLDAP_USER=""/g' /etc/sysconfig/openldap
  sed -i 's/OPENLDAP_GROUP="ldap"/"OPENLDAP_GROUP=""/g' /etc/sysconfig/openldap
  sed -i 's/OPENLDAP_KRB5_KEYTAB=""/"OPENLDAP_KRB5_KEYTAB="\/etc\/ldap.keytab"/g' /etc/sysconfig/openldap
  echo "Updated"
  sleep 1
  echo "Updating krb5.conf..."
  sed -i "s/admin_server = $CONSFQDN/admin_server = $PROVFQDN/g" /etc/krb5.conf
  sed -i "/kdc = $CONSFQDN/i kdc = $PROVFQDN" /etc/krb5.conf
  echo "Updating kdc.conf..."
  sed -i "s/ldap_servers = .*/ldap_servers = ldap:\/\/$PROVFQDN ldap:\/\/$CONSFQDN/g" /var/lib/kerberos/krb5kdc/kdc.conf
  echo "Updating krb5.conf on $PROVFQDN"
  scp -r -o 'StrictHostKeyChecking no' /etc/krb5.conf root@$PROVFQDN:/etc/krb5.conf
  echo "Updating kdc.conf on $PROVFQDN"
  scp -r -o 'StrictHostKeyChecking no' /var/lib/kerberos/krb5kdc/kdc.conf root@$PROVFQDN:/var/lib/kerberos/krb5kdc/kdc.conf
  sleep 1
  echo "Creating replication principal..."
  kadmin -p admin/admin -q "addprinc -randkey syncrepl/$CONSFQDN"
  kadmin -p admin/admin -q "ktrem -k /etc/ldap.keytab syncrepl/$CONSFQDN"
  kadmin -p admin/admin -q "ktadd -k /etc/ldap.keytab syncrepl/$CONSFQDN"
  kadmin -p admin/admin -q "ktadd -k /etc/ldap.keytab ldap/$CONSFQDN"
  kadmin -p admin/admin -q "addprinc -randkey host/$CONSFQDN"
  kadmin -p admin/admin -q "ktrem host/$CONSFQDN"
  kadmin -p admin/admin -q "ktadd host/$CONSFQDN"
  chown ldap:ldap /etc/ldap.keytab
  echo "Erasing old database..."
  rm -rf /var/lib/ldap/*
  echo "Restarting OpenLDAP..."
  echo "Restarting slapd service..."
  systemctl restart slapd
  echo "This server has been configured as a Consumer of $PROVFQDN"
  echo "Success"
fi
}

#############################
#############################
#############################
#############################
#############################
#############################
#********************#
# KERBEROS FUNCTIONS #
#********************#
#############################
#############################
#############################
#############################
#############################
#############################
#KRB5.CONF CONFIGURATION FILE
#This function configures the krb5.conf file for a kerberos admin Server and
#Master kdc
#############################
function krb5conf_gen(){
  echo "Creating krb5.conf..."
  cat <<EOF > /etc/krb5.conf
[libdefaults]
    default_realm = $KRBREALM
    forwardable = false
    proxiable = true
    clockskew = 300
    ignore_acceptor_hostname = false
    # spake_preauth_groups = edwards25519 (NOT SUPPORTED)
    noaddresses = false
    dns_lookup_realm = false
    dns_lookup_kdc = false
    allow_weak_crypto = false
    default_ccache_name = FILE:/tmp/krb5cc_%{uid}
    default_tkt_enctypes = camellia256-cts-cmac
    default_tgs_enctypes = camellia256-cts-cmac
[domain_realm]
    $DOMNAME = $KRBREALM
    .$DOMNAME = $KRBREALM

[logging]

[realms]
    $KRBREALM = {
        admin_server = $KADMIP
        kdc = $KDCIP
    }
EOF
  echo "krb5.conf generated!"
}
#############################
#KDC.CONF CONFIGURATION FILE
#This function configures the kdc.conf file for a kerberos admin Server and
#Master kdc with LDAP Database Module
#############################
# KDC.CONF GENERATOR FUNCTION
function kdcconf_gen(){
  echo "Generating kdc.conf..."
  cat <<EOF > /var/lib/kerberos/krb5kdc/kdc.conf
[kdcdefaults]
  kdc_ports = 750,88
  restrict_anonymous_to_tgt = true
[realms]
  $KRBREALM = {
      acl_file = /var/lib/kerberos/krb5kdc/kadm5.acl
      admin_keytab = FILE:/var/lib/kerberos/krb5kdc/kadm5.keytab
      default_principal_flags = +postdateable +forwardable +renewable +proxiable +dup-skey +preauth -hwauth +service +tgt-based +allow-tickets -pwchange -pwservice
      dict_file = /var/lib/kerberos/krb5kdc/kadm5.dict
      key_stash_file = /var/lib/kerberos/krb5kdc/.k5.$KRBREALM
      kdc_ports = 750,88
      max_life = 0d 10h 0m 0s
      max_renewable_life = 7d 0h 0m 0s
      database_module = ldap
      reject_bad_transit = true
      master_key_name = K/M
      supported_enctypes = camellia256-cts-cmac:normal
      }

[logging]
  kdc = FILE:/var/log/krb5/krb5kdc.log
  admin_server = FILE:/var/log/krb5/kadmind.log

[dbmodules]
  ldap = {
  db_library = kldap
  ldap_servers = $LDAPURI
  ldap_kerberos_container_dn = cn=krbContainer,$BASEDN
  ldap_kadmind_dn = uid=adm-service,ou=Services,$BASEDN
  ldap_kdc_dn = uid=kdc-service,ou=Services,$BASEDN
  ldap_service_password_file = /var/lib/kerberos/krb5kdc/$KRBREALM.keyfile
  ldap_conns_per_server = 5
  disable_last_success = false
  disable_lockout = false
  }

EOF
  echo "kdc.conf generated!"
}
#############################
#KADM5.ACL CONFIGURATION FILE
#This function configures the kadm5.acl file for manage the control access
#to the Kadmin Service.
#Principal/Role@REALM permissions (Wildcard accepted)
#############################
function kadmacl_gen(){
  echo "Generating default adm ACL..."
  echo '*/admin@'$KRBREALM'  *' > /var/lib/kerberos/krb5kdc/kadm5.acl
  echo "host/$SRVNAME@'$KRBREALM  *" >> /var/lib/kerberos/krb5kdc/kadm5.acl

}
#############################
#KERBEROS DATABASE GENERATOR
#This function configures the kerberos database
#############################
function krb_db_gen(){
  echo "Initializing Kerberos database..."
  touch /var/lib/kerberos/krb5kdc/$KRBREALM.keyfile
  /usr/lib/mit/sbin/kdb5_ldap_util stashsrvpw -f /var/lib/kerberos/krb5kdc/$KRBREALM.keyfile uid=adm-service,ou=Services,$BASEDN
  /usr/lib/mit/sbin/kdb5_ldap_util stashsrvpw -f /var/lib/kerberos/krb5kdc/$KRBREALM.keyfile uid=kdc-service,ou=Services,$BASEDN
  /usr/lib/mit/sbin/kdb5_ldap_util -D uid=adm-service,ou=Services,$BASEDN create -subtrees ou=People,$BASEDN -r $KRBREALM -s -H $LDAPURI -k camellia256-cts-cmac
}
#############################
#KERBEROS PRINCIPAL's GENERATOR
#This function creates the principals needed for the
#host and kerberos Administration services
#############################
function krb_principal_creation(){
  #CONVERSION OF SRVNAME TO LOWERCASE FOR PRINCIPALS
  PRINCHOST=$(echo $SRVNAME | tr '[:upper:]' '[:lower:]')
  #GENERATING PRINCIPALS
  echo "Generating admin/admin principal..."
  echo "You can remove this principal later"
  /usr/lib/mit/sbin/kadmin.local -q "addprinc admin/admin"
  echo "Adding principal host & keys to keytab"
  /usr/lib/mit/sbin/kadmin.local -q "addprinc -randkey host/$PRINCHOST"
  /usr/lib/mit/sbin/kadmin.local -q  "ktadd host/$PRINCHOST"
  echo "Keytab created in /etc/krb5.keytab"
  echo "Generating ldap/$PRINCHOST principal..."
  echo "Adding principal ldap host & keys to keytab"
  /usr/lib/mit/sbin/kadmin.local -q "addprinc -randkey ldap/$PRINCHOST"
  /usr/lib/mit/sbin/kadmin.local -q  "ktadd -k /etc/ldap.keytab ldap/$PRINCHOST"
  chmod 440 /etc/ldap.keytab
  chown ldap:ldap /etc/ldap.keytab
}
#############################
#############################
#############################
#############################
#############################
#############################
#   KERBEROS HA FUNCTIONS
#############################
#############################
#############################
#############################
#############################
#############################
#############################
#SLAVE KDC CONFIGURATION
#This function that configures the server provided from the master server as a slave
#in a replication environment. Should be used always from the master server to the
#replica servers. SSH should be enabled and allowed in firewall rules
#############################
function slavekdc(){
  mkdir -p $temporaldir/slave
  echo "Please make sure you have /etc/hosts and DNS correctly configured..."
  echo "Please make sure that the host principal key of this server has been already added to the main keytab"
  echo "Showing master keytab records:"
  /usr/bin/klist -k
  unset a
  read -p "Would you like to continue? (y/n)" a
  if [ "$a" = "y" ]
    then
      MASTERPRINC=$(hostname -f | tr '[:upper:]' '[:lower:]')
      read -p "Please, input the FQDN of the slave KDC: " KDCREPLICA
      REPLICAPRINC=$(echo $KDCREPLICA | tr '[:upper:]' '[:lower:]')
      echo "Adding host replica principal to keytab"
      /usr/lib/mit/sbin/kadmin.local -q "addprinc -randkey host/$REPLICAPRINC"
      /usr/lib/mit/sbin/kadmin.local -q  "ktrem host/$REPLICAPRINC"
      /usr/lib/mit/sbin/kadmin.local -q  "ktadd host/$REPLICAPRINC"
      read -p "Would you like to generate and add a ldap service principal of slave KDC to the keytab? (y/n)" a
      if [ "$a" = "y" ]
        then
      echo "Generating ldap/$REPLICAPRINC principal..."
      echo "Adding principal ldap host & keys to keytab"
      /usr/lib/mit/sbin/kadmin.local -q "addprinc -randkey ldap/$REPLICAPRINC"
      /usr/lib/mit/sbin/kadmin.local -q  "ktadd ldap/$REPLICAPRINC"
      fi
      echo "Generating replica keytab"
      /usr/lib/mit/sbin/kadmin.local -q  "ktadd -k $temporaldir/slave/krb5.keytab host/$REPLICAPRINC"
      echo "Adding replica kdc to the krb5.conf. If this procedure fails, \
      please, erase the krb5.conf and come back to the backed up original file (krb5.conf.bak)"
      cp /etc/krb5.conf /etc/krb5.conf.bak
      sleep 2
      echo "Erasing previous existing configuration..."
      sed -i "/kdc = $KDCREPLICA/d" /etc/krb5.conf
      echo "Adding new kdc to krb5.conf..."
      sed -i "/$KRBREALM = {/a           kdc = $KDCREPLICA" /etc/krb5.conf
      echo "Creating replica kdc.conf"
      #REMOVE LDAP SECTION
      cp /var/lib/kerberos/krb5kdc/kdc.conf $temporaldir/slave/kdc.conf
      sed -i '/ldap = {/,/}/d' $temporaldir/slave/kdc.conf
      sed -i '/database_module = ldap/d' $temporaldir/slave/kdc.conf
      echo "Replica kdc created..."
      echo "Adding services and configuring xinetd..."
      echo "krb5_prop stream tcp nowait root /usr/local/sbin/kpropd kpropd" >> /etc/xinetd.conf
      echo "krb5_prop       754/tcp         # Kerberos replica propagation" >> /etc/services
      echo "Restarting xinetd service..."
      systemctl restart xinetd.service
      read -p "Enter the Kerberos Realm: " REALM
      echo "" >>    $temporaldir/slave/kpropd.acl
      echo "host/$REPLICAPRINC@$KRBREALM" >> $temporaldir/slave/kpropd.acl
      echo "host/$MASTERPRINC@$KRBREALM" >>  $temporaldir/slave/kpropd.acl
      echo "Sending files to $KDCREPLICA..."
      read -p "Enter a local administrator username or root username on $KDCREPLICA: " REPLICAUSER
      scp   /etc/krb5.conf \
            $temporaldir/slave/kdc.conf \
            $temporaldir/slave/krb5.keytab \
            /var/lib/kerberos/krb5kdc/.k5.$KRBREALM \
            /var/lib/kerberos/krb5kdc/kadm5.acl \
            $temporaldir/slave/kpropd.acl \
            $REPLICAUSER@$KDCREPLICA:/tmp/
      echo "Connecting to $KDCREPLICA..."
      NTPSYNC=$(date)
      ssh $REPLICAUSER@$KDCREPLICA "echo 'Creating Temporal Folder $temporaldir.slave' && \
                                    rm -rf $temporaldir.slave && \
                                    mkdir $temporaldir.slave && \
                                    echo 'Moving all files to $temporaldir.slave' && \
                                    mv /tmp/kdc.conf $temporaldir.slave/ && \
                                    mv /tmp/.k5.$KRBREALM $temporaldir.slave/ && \
                                    mv /tmp/kadm5.acl $temporaldir.slave/ && \
                                    mv /tmp/krb5.conf $temporaldir.slave/ && \
                                    mv /tmp/krb5.keytab $temporaldir.slave/ && \
                                    mv /tmp/kpropd.acl $temporaldir.slave/ && \
                                    echo 'Stopping kadmind and krb5kdc services' && \
                                    systemctl stop kadmind.service && \
                                    systemctl stop krb5kdc.service && \
                                    echo 'Configuring xinetd and services files' && \
                                    echo 'krb5_prop stream tcp nowait root /usr/local/sbin/kpropd kpropd' >> /etc/xinetd.conf && \
                                    echo 'krb5_prop       754/tcp         # Kerberos replica propagation' >> /etc/services && \
                                    systemctl restart xinetd &&\
                                    echo 'Copying files from Temporal Folder...' && \
                                    cp $temporaldir.slave/kdc.conf /var/lib/kerberos/krb5kdc/ && \
                                    cp $temporaldir.slave/.k5.$KRBREALM /var/lib/kerberos/krb5kdc/ && \
                                    cp $temporaldir.slave/kadm5.acl /var/lib/kerberos/krb5kdc/ && \
                                    cp $temporaldir.slave/krb5.conf /etc/ && \
                                    cp $temporaldir.slave/krb5.keytab /etc/ && \
                                    cp $temporaldir.slave/kpropd.acl /var/lib/kerberos/krb5kdc/ &&\
                                    echo 'Starting and enabling kpropd...' && \
                                    /usr/lib/mit/sbin/kpropd &&\
                                    systemctl enable kpropd.service &&\
                                    #JUST FOR TESTING ENVIRONMENTS. REMOVE THIS OPTION...
                                    echo 'Syncing time between servers..' && \
                                    date -s '$NTPSYNC'"


      echo "Dumping database..."
      /usr/lib/mit/sbin/kdb5_util dump /var/lib/kerberos/krb5kdc/replica_datatrans
      echo "Replicating database..."
      /usr/lib/mit/sbin/kprop -f /var/lib/kerberos/krb5kdc/replica_datatrans $KDCREPLICA
      sleep 2
      echo "Enabling kprop service"
      systemctl enable kpropd.service
      systemctl start kpropd.service
      echo "Creating autodeploy script..."
      touch /var/log/autoreplica.log
      cat <<EOF > /var/lib/kerberos/krb5kdc/autoreplica.sh
#!/bin/bash
/usr/lib/mit/sbin/kdb5_util dump /var/lib/kerberos/krb5kdc/replica_datatrans
date >> /var/log/autoreplica.log
/usr/lib/mit/sbin/kprop -f /var/lib/kerberos/krb5kdc/replica_datatrans $KDCREPLICA >> /var/log/autoreplica.log
EOF
      chmod +x /var/lib/kerberos/krb5kdc/autoreplica.sh
      echo "Adding crontab task..."
      cat <<EOF > /tmp/crontab
*/2 * * * * /var/lib/kerberos/krb5kdc/autoreplica.sh
25 4 1,15,30 * *  rm –rf /var/log/autoreplica.log
EOF
      crontab /tmp/crontab
      echo "Crontab added..."
      echo "Starting remotely krb5kdc on $KDCREPLICA as $REPLICAUSER..."
      systemctl restart cron.service
      ssh $REPLICAUSER@$KDCREPLICA "systemctl restart krb5kdc"
      echo "Erasing master temporary files... Please find the evidences in \
      slave kdc temporal folder"
      rm -rf /tmp/krb5.conf
      rm -rf /tmp/kdc.conf
      rm -rf /tmp/krb5.keytab
      echo "SUCCESS"
      sleep 1
  fi
  main_menu;
}

logging_conf(){
  echo "Configuring logging"
  echo "local4.*    /var/log/openldap.log" >> /etc/rsyslog.conf
  echo "auth.*            /var/log/saslauthd.log" >> /etc/rsyslog.conf
  echo "Openldap LOG >> /var/log/openldap.log"
  echo "SASLAUTHD LOG >> /var/log/saslauthd.log"
}
#############################
#############################
#############################
#############################
#############################
#############################
#****************#
#       AUTH FUNCTIONS #
#****************#
#############################
#############################
#############################
#####################################################################
#PAM OR SSSD SELECTOR
#This function let you decide if yo want to use pam or sssd.
#####################################################################
function pam_sssd(){
  unset A
  unset opt
  sleep 1
  A='Select the auth configuration preferenced: '
  echo $A
  options=("PAM" \
  "SSSD")
  select opt in "${options[@]}"
  do
    case $opt in
            "PAM")
                    clear
                    zypper_pam;
                    ldapconf_gen;
                    pam_conf;
                    dir_home_gen;
                    systemctl restart nscd
                    break
            ;;
            "SSSD")
                    clear
                    zypper_sssd;
                    nsswitch_config_sssd
                    sssd_conf;
                    dir_home_gen;
                    systemctl restart sssd
                    break
            ;;

            *) echo "invalid option $REPLY";;

      esac
    done
}

#####################################################################
#ZYPPER INSTALL SSSD PACKAGES
#This function installs the SSSD required packages
#####################################################################
function zypper_sssd(){
  zypper in sssd sssd-krb5 sssd-krb5-common sssd-ldap
}

#############################
# NSSWITCH CONFIGURATION FUNCTION
# This function configures the nsswitch.conf file
#############################
function nsswitch_config_sssd(){
echo "Generating nsswitch on /etc/..."
cat <<EOF > /etc/nsswitch.conf
passwd:         compat sss
group:          compat sss

hosts:          files dns
networks:       files dns

services:       files
protocols:      files
rpc:            files
ethers:         files
netmasks:       files
netgroup:       files nis
publickey:      files

bootparams:     files
automount:      files nis
aliases:        files
sudoers:        files sss

EOF
  echo "nsswitch.conf modified!"
}
#############################
# SSSD CONFIGURATION FUNCTION
# This function configures the sssd.conf file
#############################
function sssd_conf(){
  echo "Generating sssd.conf on /etc/sssd..."
  mv /etc/sssd/sssd.conf /etc/sssd/sssd.conf.bak
  touch /etc/sssd/sssd.conf
  cat <<EOF > /etc/sssd/sssd.conf
[sssd]
config_file_version = 2
services = pam,nss,sudo
domains = $DOMNAME

[pam]
pam_account_expired_message = Account Expired, please contact an Administrator.
pam_account_locked_message = Account Locked, please contact an Administrator.

[nss]

[domain/$DOMNAME]
id_provider = ldap
auth_provider = krb5
access_provider = simple
sudo_provider = ldap
chpass_provider = krb5
enumerate = true
cache_credentials = false
case_sensitive  = true
krb5_server = $SRVNAME
krb5_backup_server = $KDC2IP
krb5_realm = $KRBREALM
krb5_rcache_dir = __LIBKRB5_DEFAULTS__
ldap_search_base = $BASEDN
ldap_uri = $LDAPURI,$LDAP2URI
ldap_sudo_search_base = ou=SUDOers,$BASEDN
ldap_user_search_base = ou=People,$BASEDN
ldap_group_search_base = ou=Group,$BASEDN
ldap_schema = rfc2307bis
ldap_tls_cacert = $TLSCA
ldap_tls_cacertdir = $TLSPATH
ldap_tls_cert = $TLSSERVER
ldap_tls_key = $TLSKEY
ldap_tls_reqcert = allow
ldap_use_tokengroups = false
ldap_sudo_full_refresh_interval = 86400
ldap_sudo_smart_refresh_interval = 3600
homedir_umask = 077
skel_dir = /etc/skel
EOF
  echo "sssd.conf generated"
  chmod 600 /etc/sssd/sssd.conf
  systemctl restart krb5kdc
}
#####################################################################
#ZYPPER INSTALL PAM PACKAGES
#This function installs the PAM required packages
#####################################################################
function zypper_pam(){
  zypper in pam_krb5 pam_krb5-32bit pam_ldap pam_ldap-32bit pam-modules pam-32bit \
  pam nss_ldap nss_ldap-32bit nscd
}
#####################################################################
#NSS_LDAP CONFIGURATION GENERATOR
#This function configures the ldap.conf with the information provided for nss_ldap
#####################################################################
function ldapconf_gen(){
  echo "Generating ldap.conf on /etc/openldap/ ..."
  echo "Backing up the old configuration ..."
  mv /etc/ldap.conf /etc/ldap.conf.bak
  cat <<EOF > /etc/ldap.conf
#LDAP Connection Options:
base                        $BASEDN
uri                         $LDAPURI,$LDAP2URI
binddn                      uid=searchuser,ou=Services,$BASEDN
bindpw                      secret
#TLS Options:
ssl                         start_tls
tls_cacertdir               $TLSPATH
tls_cacert                  $TLSCA
tls_cert                    $TLSSERVER
tls_key                     $TLSKEY
#Bind Options:
bind_policy                 soft
bind_timeout                2
nss_connect_policy          oneshot
nss_initgroups_ignoreusers  root,ldap,named,avahi,haldaemon,dbus
bind_timeout                2
nss_reconnect_tries         2
nss_reconnect_sleeptime     1
nss_reconnect_maxconntries  3
nss_base                    $BASEDN?sub?
nss_schema                  rfc2307bis
#Logging Options:
debug                       0
EOF
  echo "ldap.conf generated. Please remind to allocate the correct SSL certificates in the defined paths:"
  echo $TLSCA
  echo $TLSKEY
  echo $TLSSERVER
  echo "The nss service will now lookup as uid=searchuser,ou=Services,$BASEDN. Please configure a proper password and ACL's after deployment."
  echo "Default password: <secret>"
  chmod 644 /etc/ldap.conf
  }
#############################
# NSSWITCH CONFIGURATION FUNCTION
# This function configures the nsswitch.conf file
#############################
function nsswitch_config_pam(){
echo "Generating nsswitch on /etc/..."
cat <<EOF > /etc/nsswitch.conf
passwd:         compat ldap
group:          compat ldap

hosts:          files dns
networks:       files dns

services:       files
protocols:      files
rpc:            files
ethers:         files
netmasks:       files
netgroup:       files nis
publickey:      files

bootparams:     files
automount:      files nis
aliases:        files
sudoers:        ldap

EOF
  echo "nsswitch.conf modified!"
}
#############################
# PAM CONFIGURATION FUNCTION
# This function configures the PAM service to use SSSD
#############################
function pam_conf(){
  echo "Generating pam configuration."
  cat <<'EOF' > /etc/pam.d/common-auth
auth    required        pam_env.so
auth    optional        pam_gnome_keyring.so
auth    sufficient      pam_unix.so     try_first_pass
auth    sufficient      pam_krb5.so     use_first_pass
auth    required        pam_deny.so
EOF
  echo "common-auth generated!"

  cat <<'EOF' > /etc/pam.d/common-password
password        requisite       pam_cracklib.so
password        optional        pam_gnome_keyring.so    use_authtok
password        sufficient      pam_unix.so             use_authtok nullok shadow try_first_pass
password        required        pam_krb5.so             minimum_uid=10000
EOF
  echo "common-password generated!"

  cat <<'EOF' > /etc/pam.d/common-account
account    requisite    pam_unix.so     try_first_pass
account    sufficient   pam_localuser.so
account    sufficient   pam_ldap.so
account    required     pam_krb5.so      use_first_pass
EOF
  echo "common-account generated!"

  cat <<'EOF' > /etc/pam.d/common-session
session required        pam_limits.so
session required        pam_unix.so     try_first_pass
session optional        pam_ldap.so     try_first_pass  pam_minimum_uid=10000
session optional        pam_krb5.so     try_first_pass  minimum_uid=10000 banner=""
session optional        pam_umask.so
session optional        pam_systemd.so
session optional        pam_gnome_keyring.so    auto_start only_if=gdm,gdm-password,lxdm,lightdm
session optional        pam_env.so
EOF
  echo "common-session generated!"

  cat <<'EOF' > /etc/pam.d/login
auth     requisite  pam_nologin.so
auth     include    common-auth
account  include    common-account
password include    common-password
session  required   pam_loginuid.so
session  include    common-session
session  optional   pam_mail.so standard
session  optional   pam_ldastlog.so silent noupdate showfailed
EOF
  echo "login configured!"
}

#############################
# PAM CONFIGURATION - DIRECTORY HOME CREATION
# This function configures the PAM service to create the users home directory
#############################
function dir_home_gen(){
  unset a
  read -p "Would you like to create the home directory logged users?(y/n)" a
  if [ "$a" = "y" ]
    then
      echo "Generating pam configuration."
      echo "session  optional       pam_mkhomedir.so" >> /etc/pam.d/common-session
      sleep 1
      echo "common-session modified!"
  fi
}
#############################
#############################
#############################
#############################
#############################
#############################
#****************#
#       SSH FUNCTIONS
#****************#
#############################
#############################
#############################
#############################
#############################
#############################
#############################
# SSH KERBEROS CONFIG GENERATOR
# This function enables kerberos as auth source to use ssh
#############################
function krb5_ssh_gen(){
  echo "Backing up sshd_config to /etc/ssh/sshd_config"
  mv /etc/ssh/sshd_config /etc/ssh/sshd_config.orig
#Please adecuate this file to your needs. SSH SERVER.
#Disables all non-GSSAPI connections by default.
  cat <<EOF > /etc/ssh/sshd_config
AllowGroups root
LogLevel VERBOSE
PermitRootLogin yes
AuthorizedKeysFile      .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication yes
KerberosAuthentication yes
KerberosTicketCleanup yes
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
GSSAPIStrictAcceptorCheck yes
GSSAPIKeyExchange yes
X11Forwarding yes
UseDNS yes
#Banner /etc/motd
Subsystem       sftp    /usr/lib/ssh/sftp-server
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL
#UsePAM=no --> to use only GSSAPI Authentication thorugh SSH.
UsePAM=yes
EOF
#Please adecuate this file to your needs. SSH CLIENT
  echo "Backing up ssh_config to /etc/ssh/ssh_config"
  mv /etc/ssh/ssh_config /etc/ssh/ssh_config.orig
  cat <<EOF > /etc/ssh/ssh_config
Host *
ForwardX11Trusted yes
SendEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
SendEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
SendEnv LC_IDENTIFICATION LC_ALL
GSSAPIAuthentication yes
GSSAPIDelegateCredentials yes
GSSAPIKeyExchange yes
GSSAPITrustDNS yes
EOF
  systemctl restart sshd.service
  sleep 1
  echo "SSH GSSAPI enabled! You can revert the changes at any moment replacing the new files with the original .orig files."
}
#############################
#############################
#############################
#******************#
#  OTHER FUNCTIONS #
#******************#
#############################
#############################
#############################
#############################
#############################
#############################
#SUDO GROUPS CREATOR
#This function makes easier to add new LDAP groups to the LDAP SUDOers OU
#############################
sudoers_add(){
  read -p "Please, provide the name of the group you would like to add: " SUDOGROUP
  read -p "Please, provide the sudoers base search eg. ou=SUDOers,dc=domain,dc=com: " SUDOBASE

  cat <<EOF > $temporaldir/sudogroup.ldif
dn: cn=%$SUDOGROUP,$SUDOBASE
objectClass: top
objectClass: sudoRole
cn: %$SUDOGROUP
sudoUser: %$SUDOGROUP
sudoHost: ALL
sudoCommand: ALL
EOF
  read -p "Please, provide the LDAP hostname: " LDAPHOST
  read -p "Please, provide the BIND DN: " BINDDN
  ldapadd -x -D $BINDDN -W -h $LDAPHOST -f $temporaldir/sudogroup.ldif
  echo "$SUDOGROUP added to Sudoers"
}
#############################
#TEMPORAL FOLDER CREATION
#Restart most of the involved services
#############################
temporal_directory(){
if [ -d $temporaldir ];
then
echo "$temporaldir already exists. Renaming old directory"
mv $temporaldir $temporaldir.old.$RANDOM
else
echo "Creating $temporaldir"
fi
mkdir -p $temporaldir
echo "$temporaldir created!"
}
#############################
#TEMPORAL FOLDER CREATION
#Restart most of the involved services
#############################
function purge_files(){
  unset a
  read -p "Would you like to remove all temporal files?(Y/N): " a
  if [ "$a" = "y" ]
    then
      echo "Deleting all files..."
      rm -rf $temporaldir*
      sleep 2
      echo "Temporal files erased"
      exit
  fi
}
#############################
#RESTART ALL SERVICES
#Restart most of the involved services
#############################
function resetall(){
  echo "Restarting and enabling services..."
  systemctl stop kadmind
  systemctl stop krb5kdc
  systemctl stop slapd
  systemctl enable kadmind
  systemctl enable krb5kdc
  systemctl enable slapd
  systemctl start slapd
  systemctl start kadmind
  systemctl start krb5kdc
}
###########################################
# CONFIGURE LOGON MANAGEMENT
#This funcion configures interactively the NSSWITCH, SSSD and PAM services
# Is used to reconfigure the SSSD service when more KDC's are involved in a replica environment
function conf_logon(){
  read -p "Please input the FQDNs of KRB5 Servers involved in logon process (separated by commas): " KRB5SERVERS
  read -p "Please input the ldap URIs of LDAP Servers involved in logon process (separated by commas): " LDAPSERVERS
  read -p "Please input the LDAP search base, e.g dc=domain,dc=com: " BASEDN
  read -p "Please input the LDAP Users search base, e.g ou=People,dc=domain,dc=com: " BASEUSERS
  read -p "Please input the LDAP Groups search base, e.g ou=Groups,dc=domain,dc=com: " BASEGROUPS
  read -p "Please input the KRB5 REALM, e.g DOMAIN.COM: " KRBREALM
  echo "Erasing old configuration..."
  sed -i '/id_provider =.*/d' /etc/sssd/sssd.conf
  sed -i '/auth_provider =.*/d' /etc/sssd/sssd.conf
  sed -i '/krb5_server =.*/d' /etc/sssd/sssd.conf
  sed -i '/ldap_uri =.*/d' /etc/sssd/sssd.conf
  sed -i '/ldap_search_base =.*/d' /etc/sssd/sssd.conf
  sed -i '/krb5_realm =.*/d' /etc/sssd/sssd.conf
  sed -i '/krb5_realm =.*/d' /etc/sssd/sssd.conf
  sed -i '/ldap_search_user_base =.*/d' /etc/sssd/sssd.conf
  sed -i '/ldap_search_group_base =.*/d' /etc/sssd/sssd.conf

  echo "Adding new parameters..." /etc/sssd/sssd.conf
  sed -i '/^\[domain.*/a id_provider = ldap' /etc/sssd/sssd.conf
  sed -i '/^id_provider.*/a auth_provider = krb5' /etc/sssd/sssd.conf
  sed -i "/^auth_provider*/a krb5_server = $KRB5SERVERS" /etc/sssd/sssd.conf
  sed -i "/^krb5_server*/a ldap_uri = $LDAPSERVERS" /etc/sssd/sssd.conf
  sed -i "/^ldap_uri*/a ldap_search_base = $BASEDN" /etc/sssd/sssd.conf
  sed -i "/^ldap_search_base*/a ldap_search_user_base = $BASEUSERS" /etc/sssd/sssd.conf
  sed -i "/^ldap_search_base*/a ldap_search_group_base = $BASEGROUPS" /etc/sssd/sssd.conf
  sed -i "/^ldap_search_base*/a krb5_realm = $KRBREALM" /etc/sssd/sssd.conf
  unset a
  read -p "Would you like to enable sudo by LDAP? Please, note that configuration should be done before enabling it (y/n): " a
  if [ "$a" = "y" ]
    then
      read -p "Please input the ldap URIs of LDAP SUDO Search Base, eg:ou=SUDOers,dc=domain,dc=com: " LDAPSUDO
      echo "Erasing old sudo configuration: "
      sed -i '/ldap_sudo_search_base =.*/d' /etc/sssd/sssd.conf
      sed -i '/\[sudo\]/d' /etc/sssd/sssd.conf
      sed -i '/ldap_sudo_full_refresh_interval=.*/d' /etc/sssd/sssd.conf
      sed -i '/ldap_sudo_smart_refresh_interval=.*/d' /etc/sssd/sssd.conf
      sed -i '/sudoers=.*/d' /etc/nsswitch.conf

      echo "Adding sudo parameters"
      sed -i "/^krb5_realm*/a ldap_sudo_search_base = $LDAPSUDO" /etc/sssd/sssd.conf
      sed -i '/^ldap_sudo_search_base*/a sudo_provider = ldap' /etc/sssd/sssd.conf
      sed -i '/^sudo_provider*/a ldap_sudo_full_refresh_interval=86400' /etc/sssd/sssd.conf
      sed -i '/^ldap_sudo_full_refresh_interval*/a ldap_sudo_smart_refresh_interval=3600' /etc/sssd/sssd.conf
      echo "[sudo]" >> /etc/sssd/sssd.conf
      sed -i 's/^services =.*/pam,nss,sudo/g' /etc/sssd/sssd.conf
      echo "sudoers:        sss" >> /etc/nsswitch.conf
  fi
  unset a
  read -p "Would you like to enable access provider and login restriction by LDAP groups? (y/n): " a
  if [ "$a" = "y" ]
    then
      read -p "Please input the ldap groups separated by commas, eg:Administrators,Operators: " LDAPGROUP
      echo "Erasing old access configuration: "
      sed -i '/access_provider =.*/d' /etc/sssd/sssd.conf
      sed -i '/simple_allow_groups =.*/d' /etc/sssd/sssd.conf
      echo "Adding access parameters"
      sed -i '/^auth_provider*/a access_provider = simple/' /etc/sssd/sssd.conf
      sed -i '/^access_provider*/a simple_allow_groups = $LDAPGROUP/' /etc/sssd/sssd.conf
    fi
  nsswitch_config_sssd;
  pam_conf;
  dir_home_gen;
}

function configure_saslauthd(){
  echo "You will need an internet connection with active SUSE subscription to official repositories. Otherwise insert DVD/CD"
  echo "Would you like to continue?[y/n]"
  read a
  if [ "$a" = "y" ]
  then
    echo "Installing SERVER packages. Please wait..."
    zypper refresh
    zypper in -y cyrus-sasl cyrus-sasl-gssapi cyrus-sasl-saslauthd
    echo "All packages has been installed."
  else
    break
fi
  unset $a
  unset $b
  read -p "Enter the hostname... :" a
  read -p "Enter the REALM... :" b
  read -p "Enter the LDAP keytab location: " c
  read -p "Enter BASEDN: " d
  echo "Configuring slapd.conf for sasl2"
  cat <<EOF > /etc/sasl2/slapd.conf
mech_list: gssapi digest-md5 cram-md5 external
pwcheck_method: saslauthd
saslauthd_path: /var/run/sasl2/mux
keytab: $c
EOF
  echo "/etc/sasl2/slapd.conf configured"
  cp /etc/sasl2/slapd.conf /usr/lib64/sasl2/slapd.conf
  echo "Configuring saslauthd on sysconfig"
  cat <<EOF > /etc/sysconfig/saslauthd
SASLAUTHD_AUTHMECH=pam
SASLAUTHD_THREADS=5
SASLAUTHD_PARAMS=""
SOCKETDIR=/var/run/sasl2
FLAGS="-O /etc/saslauthd.conf"
EOF
  echo "Adding ldap to sasl group..."
  groupadd sasl
  usermod -a -G sasl ldap
  cat <<EOF > $temporaldir/saslauthd.ldif
dn: cn=config
changetype: modify
replace: olcSaslSecProps
olcSaslSecProps: none
-
replace: olcSaslHost
olcSaslHost: $a
-
replace: olcSaslRealm
olcSaslRealm: $b
EOF
  ldapmodify -Y EXTERNAL -H ldapi:/// -f $temporaldir/saslauthd.ldif
  echo "Configuring AuthzRegexp..."
  cat <<EOF > $temporaldir/authregexp.ldif
dn: cn=config
changetype: modify
add: olcAuthzRegexp
olcAuthzRegexp: {0}uid=([^,]*),cn=$KRBREALM,cn=gssapi,cn=auth uid=$1,$d
EOF
  ldapadd -Y EXTERNAL -H ldapi:/// -f $temporaldir/authregexp.ldif
  echo "Restarting LDAP..."
  systemctl enable saslauthd
  systemctl start saslauthd
  systemctl restart slapd
  echo "Configured Successfully"
  sleep 2
  main_menu;
}
#############################
#############################
#############################
#############################
#############################
#############################
#**************************************#
# MAIN FUNCTIONS #
#These Functions controls the workflow #
#**************************************#
#############################
#############################
#############################
#############################
#############################
# CREATING NEW MASTER AUTH SERVER
#This function runs the required functions to
#create a new master standalone authentication server
#with ldap and kerberos.
#############################
function new_srv(){
  echo "Please, note that this option is to deploy a new standalone authentication server (LDAP + KERBEROS). Since a standalone is required to configure a server as a replica later, please define\
  all environments pointing to this server."
  interactive_mode;
  sleep 1
  echo ""
  #Install packages
  zypper_pack_srv;
  sleep 1
  echo ""
  #-OPENLDAP CONFIGURATION-#
  #ldap daemon configuration
  ldap_service_conf;
  #slapd.conf generator and slapd.d
  slapd_gen;
  sleep 1
  echo ""
  #ldap password function
  ldap_pw_gen;
  #Config and schema import
  schema_import;
  sleep 1
  echo ""
  #backend.ldif generator
  backend_gen;
  sleep 1
  echo ""
  #basedomain.ldif generator
  basedomain_gen;
  #Adding SSL configuration
  ssl_ldap_gen;
  #Setting up Systemd Service
  echo "Restarting slapd service..."
  systemctl restart slapd
  echo "OPENLDAP AUTH SERVER CORRECTLY DEPLOYED!"
  sleep 1
  #-KERBEROS CONFIGURATION-#
  echo "Kerberizing system..."
  export KRB5_CONFIG=/etc/krb5.conf
  export KRB5_KDC_PROFILE=/var/lib/kerberos/krb5kdc/kdc.conf
  krb5conf_gen;
  #kdc.conf generator
  kdcconf_gen;
  #kadm5.acl generator
  kadmacl_gen;
  #database generator
  krb_db_gen;
  #admin principal generator
  krb_principal_creation;
  sleep 1
  echo ""
  #Adding ACLs...
  frontendacl;
  #Adding ACL's
  #ldapaclroot;
  #PAM or SSD
  pam_sssd;
  #Assign permissions
  chmod 440 /etc/krb5.keytab
  chmod 644 /etc/nsswitch.conf
  logging_conf;
  harden_objects;
  #starting and enabling the services
  resetall;
  echo "SYSTEM DEPLOYED!"
  sleep 4
  main_menu;
}
#############################
# CREATING NEW SLAVE KDC
#This function runs the required functions to
#transform a standalone authentication server
#with ldap and kerberos into a slave KDC in a replication environment
#############################
function new_slavekdc(){
  echo "Please, note that this option requires to have a KRB5KDC Server already deployed on a server in the same network. This server\
  should be the Master KDC and will replicate some files into the desired slave KDC. Please check that both date systems are correctly synced"
  unset a
  read -p "Would you like to continue? (y/n)" a
  if [ "$a" = "y" ]
    then
      slavekdc;
      sleep 4
  fi
  main_menu;
}
#############################
# ENABLING SYNC PROVIDER
#This function runs the required functions to
#transform a standalone authentication server
#with ldap and kerberos into a Sync Provider in a replication environment
#############################
function enable_syncprovider(){
  echo "Please, note that this option requires to have a LDAP Auth Server already deployed on this server"
  unset a
  read -p "Would you like to continue?(y/n): " a
  if [ "$a" = "y" ]
    then
      provider;
      sleep 4
  fi
}
#############################
# ENABLING SYNC CONSUMER
#This function runs the required functions to
#transform a standalone authentication server
#with ldap and kerberos into a Sync Consumer in a replication environment
#############################
function enable_syncconsumer(){
  echo "Please, note that this option requires to have a LDAP Auth Server already deployed on this server"
  unset a
  read -p "Would you like to continue?(y/n): " a
  if [ "$a" = "y" ]
    then
      consumer;
      sleep 4
  fi
  main_menu;
}


function enable_syncconsumersasl(){
  echo "Please, note that this option requires to have a LDAP Auth Server already deployed on this server"
  unset a
  read -p "Would you like to continue?(y/n): " a
  if [ "$a" = "y" ]
    then
      consumersasl;
      sleep 4
  fi
  main_menu;
}

####################################################
#PAM RECONFIGURE
####################################################
function reconf_pam(){
  echo "Please, note that this option will reconfigure the pam authentication service and nsswitch"
  unset a
  read -p "Would you like to continue?(y/n): " a
  if [ "$a" = "y" ]
    then
      pam_conf;
      dir_home_gen;
      nsswitch_config;
      sleep 2
  fi
  main_menu;
}
#############################
#############################
#############################
#############################
#############################
# PROGRAM EXECUTION   #
#############################
#Temporal Directory creation:
clear
temporal_directory;
sleep 3
#Root checker
root_chck;
#Main Menu
main_menu;
#############################
#############################
#############################
#############################
