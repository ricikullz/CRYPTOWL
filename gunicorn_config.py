import os


workers = int(os.environ.get('GUNICORN_PROCESSES', '4'))
threads = int(os.environ.get('GUNICORN_THREADS', '8'))
bind = os.environ.get('GUNICORN_BIND', '127.0.0.1:8080')
# <--- Certificate and Private key files (CRT and PEM) for SSL/TLS connection (Paste your own paths)
# certfile = '/etc/somedirpath/cert.crt'
# keyfile = '/etc/somedirpath/privkey.pem'
# ca_certs = '/etc/somedirpath/ca_cert.crt'
# --->
forwarded_allow_ips = '*'
secure_scheme_headers = {'X-FORWARDED-PROTOCOL': 'ssl', 'X-FORWARDED-PROTO': 'https', 'X-FORWARDED-SSL': 'on'}