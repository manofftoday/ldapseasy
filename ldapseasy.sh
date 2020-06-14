#!/bin/bash
########################################################################
#Script Name	: LDAPSEASY                                                                  
#Description	: Generate autosigned certificates in pem format to use to deploy OpenLDAP                                                            
#Args           :                                                                                           
#Author       	: Dari Garcia (manofftoday)                                              
#GitHub         : https://github.com/manofftoday                                     
########################################################################
echo "Welcome to LDAPSeasy!"
read -p "Enter the Host FQDN: " FQDN
echo "Creating certificate..."
openssl req -newkey rsa:1024 -x509 -nodes \
                -out $FQDN.pem -keyout $FQDN.key.pem -days 3650
chown -v $FQDN.pem
chmod -v 400 $FQDN.pem
chown -v $FQDN.key.pem
chmod -v 400 $FQDN.key.pem
echo "Created"
