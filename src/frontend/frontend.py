import datetime
import json
import logging
import os
import socket
from decimal import Decimal

import requests
from requests.exceptions import HTTPError, RequestException
import jwt
from flask import Flask, abort, app, jsonify, make_response, redirect, \
    render_template, request, url_for

from opentelemetry import trace
from opentelemetry.sdk.trace.export import BatchExportSpanProcessor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.propagators import set_global_textmap
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.tools.cloud_trace_propagator import CloudTraceFormatPropagator
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.jinja2 import Jinja2Instrumentor


def create_app():
    """Flask application factory to create instances
    of the Frontend Flask App
    """
    app = Flask(__name__)

    @app.route("/")
    def root():
        """
            Renders home page or login page, depending on authentication status.
        """
        token = request.cookies.get(app.config['TOKEN_NAME'])
        # if not verify_token(token):
        #    return login_page()
        return home()

    @app.route("/home")
    def home():
        """
        Renders home page. Redirects to /login if token is not valid
        """
        token = request.cookies.get(app.config['TOKEN_NAME'])
        # if not verify_token(token):
        # user isn't authenticated
        #    app.logger.debug(
        #        "User isn\ 't authenticated. Redirecting to login page.")
        #    return redirect(url_for('login_page',
        #                            _external=True,
        #                            _scheme=app.config['SCHEME']))
        #token_data = jwt.decode(token, verify=False)

        # page followed by variables to be used
        return render_template('index.html',
                               site_name="Prison Inventory Manager")

    @app.route("/inventory")
    def inventory():
        """
        Renders inventory page. Redirects to /login if token is not valid
        """
        token = request.cookies.get(app.config['TOKEN_NAME'])
        # if not verify_token(token):
        # user isn't authenticated
        #    app.logger.debug(
        #        "User isn\ 't authenticated. Redirecting to login page.")
        #    return redirect(url_for('login_page',
        #                            _external=True,
        #                            _scheme=app.config['SCHEME']))
        #token_data = jwt.decode(token, verify=False)

        # page followed by variables to be used
        return render_template('inventory.html',
                               site_name="Prison Inventory Manager")

    @app.route("/inventory/equipment")
    def inventoryEquipment():
        """
        Renders inventory page. Redirects to /login if token is not valid
        """
        token = request.cookies.get(app.config['TOKEN_NAME'])
        # if not verify_token(token):
        # user isn't authenticated
        #    app.logger.debug(
        #        "User isn\ 't authenticated. Redirecting to login page.")
        #    return redirect(url_for('login_page',
        #                            _external=True,
        #                            _scheme=app.config['SCHEME']))
        #token_data = jwt.decode(token, verify=False)

        # page followed by variables to be used
        return render_template('inventory.html',
                               site_name="Prison Inventory Manager")

    def verify_token(token):
        """
        Validates token using userservice public key
        """
        app.logger.debug('Verifying token.')
        if token is None:
            return False
        try:
            jwt.decode(
                token, key=app.config['PUBLIC_KEY'], algorithms='RS256', verify=True)
            app.logger.debug('Token verified.')
            return True
        except jwt.exceptions.InvalidTokenError as err:
            app.logger.error('Error validating token: %s', str(err))
            return False

    @app.route("/login", methods=['GET'])
    def login_page():
        """
        Renders login page. Redirects to /home if user already has a valid token
        """
        token = request.cookies.get(app.config['TOKEN_NAME'])
        if verify_token(token):
            # already authenticated
            app.logger.debug(
                'User already authenticated. Redirecting to /home')
            return redirect(url_for('home',
                                    _external=True,
                                    _scheme=app.config['SCHEME']))

        return render_template('login.html',
                               cymbal_logo=os.getenv('CYMBAL_LOGO', 'false'),
                               cluster_name=cluster_name,
                               pod_name=pod_name,
                               pod_zone=pod_zone,
                               message=request.args.get('msg', None),
                               default_user=os.getenv('DEFAULT_USERNAME', ''),
                               default_password=os.getenv(
                                   'DEFAULT_PASSWORD', ''),
                               bank_name=os.getenv('BANK_NAME', 'Bank of Anthos'))

    @app.route('/login', methods=['POST'])
    def login():
        """
        Submits login request to userservice and saves resulting token
        Fails if userservice does not accept input username and password
        """
        return _login_helper(request.form['username'],
                             request.form['password'])

    def _login_helper(username, password):
        try:
            app.logger.debug('Logging in.')
            req = requests.get(url=app.config["LOGIN_URI"],
                               params={'username': username, 'password': password})
            req.raise_for_status()  # Raise on HTTP Status code 4XX or 5XX

            # login success
            token = req.json()['token'].encode('utf-8')
            claims = jwt.decode(token, verify=False)
            max_age = claims['exp'] - claims['iat']
            resp = make_response(redirect(url_for('home',
                                                  _external=True,
                                                  _scheme=app.config['SCHEME'])))
            resp.set_cookie(app.config['TOKEN_NAME'], token, max_age=max_age)
            app.logger.info('Successfully logged in.')
            return resp
        except (RequestException, HTTPError) as err:
            app.logger.error('Error logging in: %s', str(err))
        return redirect(url_for('login',
                                msg='Login Failed',
                                _external=True,
                                _scheme=app.config['SCHEME']))

    # set up global variables
    app.config["TRANSACTIONS_URI"] = 'http://{}/transactions'.format(
        os.environ.get('TRANSACTIONS_API_ADDR'))
    app.config["USERSERVICE_URI"] = 'http://{}/users'.format(
        os.environ.get('USERSERVICE_API_ADDR'))
    app.config["BALANCES_URI"] = 'http://{}/balances'.format(
        os.environ.get('BALANCES_API_ADDR'))
    app.config["HISTORY_URI"] = 'http://{}/transactions'.format(
        os.environ.get('HISTORY_API_ADDR'))
    app.config["LOGIN_URI"] = 'http://{}/login'.format(
        os.environ.get('USERSERVICE_API_ADDR'))
    app.config["CONTACTS_URI"] = 'http://{}/contacts'.format(
        os.environ.get('CONTACTS_API_ADDR'))
    # app.config['PUBLIC_KEY'] = open(os.environ.get('PUB_KEY_PATH'), 'r').read()
    app.config['LOCAL_ROUTING'] = os.getenv('LOCAL_ROUTING_NUM')
    # timeout in seconds for calls to the backend
    app.config['BACKEND_TIMEOUT'] = 4
    app.config['TOKEN_NAME'] = 'token'
    app.config['TIMESTAMP_FORMAT'] = '%Y-%m-%dT%H:%M:%S.%f%z'
    app.config['SCHEME'] = os.environ.get('SCHEME', 'http')

    # where am I?
    metadata_url = 'http://metadata.google.internal/computeMetadata/v1/'
    metadata_headers = {'Metadata-Flavor': 'Google'}
    # get GKE cluster name
    cluster_name = "unknown"
    try:
        req = requests.get(metadata_url + 'instance/attributes/cluster-name',
                           headers=metadata_headers)
        if req.ok:
            cluster_name = str(req.text)
    except (RequestException, HTTPError) as err:
        app.logger.warning("Unable to capture GKE cluster name.")

    # get GKE pod name
    pod_name = "unknown"
    pod_name = socket.gethostname()

    # get GKE node zone
    pod_zone = "unknown"
    try:
        req = requests.get(metadata_url + 'instance/zone',
                           headers=metadata_headers)
        if req.ok:
            pod_zone = str(req.text.split("/")[3])
    except (RequestException, HTTPError) as err:
        app.logger.warning("Unable to capture GKE node zone.")

    # register formater functions
    # app.jinja_env.globals.update(format_currency=format_currency)
    # app.jinja_env.globals.update(format_timestamp_month=format_timestamp_month)
    # app.jinja_env.globals.update(format_timestamp_day=format_timestamp_day)

    # Set up logging
    app.logger.handlers = logging.getLogger('gunicorn.error').handlers
    app.logger.setLevel(logging.getLogger('gunicorn.error').level)
    app.logger.info('Starting frontend service.')

    # Set up tracing and export spans to Cloud Trace.
   # if os.environ['ENABLE_TRACING'] == "true":
   #     app.logger.info("✅ Tracing enabled.")
   #     trace.set_tracer_provider(TracerProvider())
   #     cloud_trace_exporter = CloudTraceSpanExporter()
   #     trace.get_tracer_provider().add_span_processor(
   # BatchExportSpanProcessor(cloud_trace_exporter)
    #    )
    #    set_global_textmap(CloudTraceFormatPropagator())
    # Add tracing auto-instrumentation for Flask, jinja and requests
    #    FlaskInstrumentor().instrument_app(app)
    #    RequestsInstrumentor().instrument()
    #    Jinja2Instrumentor().instrument()
    # else:
    app.logger.info("🚫 Tracing disabled.")

    return app


if __name__ == "__main__":
    # Create an instance of flask server when called directly
    FRONTEND = create_app()
    FRONTEND.run()
