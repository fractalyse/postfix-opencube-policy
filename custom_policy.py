#!/usr/bin/env python3

# Copyrigth Fractalyse

import sys
import ldap
import configparser
import logging
import os

log_file = "/var/log/mail/policy_service.log"

os.makedirs("/var/log/mail/", exist_ok=True)

if not os.path.exists(log_file):
  with open(log_file, "w") as file:
    file.write("")
os.chown("log_file", "root", "nobody")

logging.basicConfig(
   filename=log_file,
   level=logging.DEBUG,
   format='%(asctime)s - %(levelname)s - %(message)s'
)




config = configparser.ConfigParser()
config.read("/etc/postfix/postfix-files.d/sender_login_maps")
ldap_server = config.get('DEFAULT', "ldap_server")
ldap_user = config.get('DEFAULT', "ldap_user")
ldap_password = config.get('DEFAULT', "ldap_password")
ldap_search_dn = config.get('DEFAULT', "ldap_search_dn")
ldap_filter = config.get('DEFAULT', "ldap_filter")
ldap_filter_spoof = config.get('DEFAULT', "ldap_filter_spoof")
ldap_attr = [item.strip() for item in config.get('DEFAULT', "ldap_attr").split(",")]

class LDAPConnection:
   """
   LDAP connexion manager for persistant connection
   Gestionnaire de connexion LDAP pour garantir la gestion sécurisée et persistante des connexions.
   """
   def __init__(self, server, user, password):
      self.server = server
      self.user = user
      self.password = password
      self.conn = None

   def __enter__(self):
      self.conn = ldap.initialize(self.server)
      self.conn.simple_bind_s(self.user, self.password)
      return self.conn

   def __exit__(self, exc_type, exc_value, traceback):
      if self.conn:
         self.conn.unbind()


def ldap_query(conn, base_filter, **kwargs):
   """
   Query LDAP with filter
   Effectuer une requête LDAP avec un filtre formaté.
   """
   filter_query = base_filter.format(**kwargs)
   try:
      result = conn.search_s(ldap_search_dn, ldap.SCOPE_SUBTREE, filter_query, ldap_attr)
      query = {}
      for dn, entry in result:
         query[dn] = {attr: values[0].decode('utf-8') for attr, values in entry.items()}
      return query
   except ldap.LDAPError as e:
      logging.error(f"LDAP query failed: {e}")
      return {}

def parse_request():
   """
   Read and anylise request from stdin
   Lire et analyser la requête standard entrée.
   """
   request = {}
   for line in sys.stdin:
      line = line.strip()
      if not line:
         break
      if "=" in line:
         key, value = line.split("=", 1)
         request[key.strip()] = value.strip()
      else:
         logging.warning(f"Invalid line in request: {line}")
   return request

def is_authorized(query, sasl_username, domain, sender):
   """
   Verify if SASL user is authorized to use current alias
   Vérifier si un utilisateur SASL est autorisé à utiliser l'alias courant
   """
   for dn, attributes in query.items():
      if (
            attributes.get("mailaliasfrom") == domain and
            attributes.get("mailaliasto") == sasl_username
      ) or (
            attributes.get("mailaliasto") == sasl_username and
            attributes.get("mailaliasfrom") == sender
         ):
         return True
   return False


def is_spoofing(query_spoof, mail_from, sasl_username):
   """
   Verify if user is trying to spoof existing email address
   Vérifier si un utilisateur essaye d'usurper un email existant
   """
   for dn, attributes in query_spoof.items():
      if (attributes.get("mailaliasfrom") == mail_from and
          sasl_username != attributes.get("mailaliasto")):
         return True
   return False

def main():
   # Read postfix request
   request = parse_request()
   # bind variables
   sasl_username = request.get("sasl_username")
   mail_from = request.get("sender")
   # user is not logged with sasl
   if not sasl_username:
      logging.info("No SASL username provided, action=dunno")
      print("action=dunno")
      return

   sender_mail_user = sasl_username.split("@")[0]
   sender_mail_domain = "@" + sasl_username.split("@")[1]

   try:
      # Allow sending if SASL user is the same as sender
      # Autoriser l'envoi si SASL correspond à l'adresse expéditeur
      if sasl_username == mail_from:
         logging.info(f"SASL user {sasl_username} sending from their own address {mail_from}")
         print("action=permit")
         return

      with LDAPConnection(ldap_server, ldap_user, ldap_password) as conn:
         # Query LDAP
         # Effectuer les requêtes LDAP
         query = ldap_query(conn, ldap_filter, sasl_username=sasl_username)
         query_spoof = ldap_query(conn, ldap_filter_spoof, sender_mail=mail_from)
      # Verify and decide
      # Vérifications et décisions
      if is_authorized(query, sasl_username, sender_mail_domain, mail_from):
         if not is_spoofing(query_spoof, mail_from, sasl_username):
            logging.info(f"Authorized: SASL user {sasl_username} can send as {mail_from}")
            print("action=permit")
            return

      # Else default action
      # Sinon, action par défaut
      logging.warning(f"Unauthorized: SASL user {sasl_username} tried to send as {mail_from}")
   except Exception as e:
      logging.error(f"Unexpected error: {e}")
      print("action=defer_if_permit")
      return

   print("action=dunno")

if __name__ == "__main__":
   main()
   print("")
