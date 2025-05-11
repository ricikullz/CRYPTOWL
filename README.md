# CRYPTOWL

## Send and Read encrypted messages

CRYPTOWL is a simple web application written in Python (Flask) for sending and reading encrypted messages.

It uses:

* **DB**: MariaDB or MySQL + PyMySql
* **Encryption**: pycriptodome, cryptography and secrets
* **WSGI HTTP Server**: Gunicorn

### Installation

1. Consider you already unpacked the app archive file. First you have to create virtual environment and activate it:
```
cd cryptowl
python3 -m venv .venv
. .venv/bin/activate
```
**NOTE**: If you want to make some changes to CRYPTOWL - make it while virtual environment is activated. Don't forget to exit virtual environment after you finish your work:
```
deactivate
```

2. Install all required modules using:
```
pip install -r requirements
```
3. Create database (MariaDB/MySQL) on your server and then edit this values in ``app_config_prod.py`` configurration file:
```
MYSQL_HOST = 'Your host value'
MYSQL_DB = 'Name of your DB'
MYSQL_USER = 'DB username'
MYSQL_PASSWORD = 'Password for DB username'
```
4. Install certificate and private key pair to have fully secured connection (this is required unless you believe that users just have a GOOD FAITH in your web site). Edit this lines in ``gunicorn_config.py`` configuration file and then uncomment these lines:
```
certfile = '/etc/somedirpath/cert.crt' <--- Edit to your path value
keyfile = '/etc/somedirpath/privkey.pem' <--- Edit to your path value
ca_certs = '/etc/somedirpath/ca_cert.crt' <--- Edit to your path value
```
Make other Gunicorn and application configuration changes if needed.

5. Run the application with this command:
```
gunicorn --config gunicorn_config.py app:app
```

### Recommendations

As Gunicorn developers advise on [their web page](https://gunicorn.org/#deployment) you should use Nginx HTTP server in pair with Gunicorn. How to setup all of it? Just google it or read the Gunicorn [official manual](https://docs.gunicorn.org/en/latest/deploy.html).