import datetime
import json
import logging
import os
import socket
from decimal import Decimal

import requests
from requests.exceptions import HTTPError, RequestException
import jwt
from flask import Flask, abort, jsonify, make_response, redirect, \
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
        if not verify_token(token):
            return login_page()
        return home()

    @app.route("/home")
    def home():
        """
        Renders home page. Redirects to /login if token is not valid
        """
       token = request.cookies.get(app.config['TOKEN_NAME'])
        if not verify_token(token):
            # user isn't authenticated
            app.logger.debug("User isn\ 't authenticated. Redirecting to login page.")
            return redirect(url_for('login_page',
                                                _external=True,
                                                _scheme=app.config['SCHEME']))
        token_data = jwt.decode(token, verify=False)

        # page followed by variables to be used
        return render_template('index.html')

    def verify_token(token):
        """
        Validates token using userservice public key
        """
        app.logger.debug('Verifying token.')
        if token is None:
            return False
        try:
            jwt.decode(token, key=app.config['PUBLIC_KEY'], algorithms='RS256', verify=True)
            app.logger.debug('Token verified.')
            return True
        except jwt.exceptions.InvalidTokenError as err:
            app.logger.error('Error validating token: %s', str(err))
            return False
