import pytz
from boto import sts, iam
from datetime import datetime
from flask import Flask, jsonify, current_app

app = Flask(__name__)

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
REGION = "us-west-2"


@app.route('/latest/meta-data/public-keys/0')
def handle_public_key_0():
    return "openssh-key"


@app.route('/latest/meta-data/public-keys')
def handle_public_keys():
    return "0=my-public-key"


@app.route('/latest/meta-data/reservation-id')
def handle_reservation_id():
    return "r-00000000"


@app.route('/latest/meta-data/local-ipv4')
@app.route('/latest/meta-data/public-ipv4')
def handle_local_ipv4():
    return "127.0.0.1"


@app.route('/latest/meta-data/ami-id')
def handle_ami_id():
    return "a-00000000"


@app.route('/latest/meta-data/local-hostname')
@app.route('/latest/meta-data/hostname')
@app.route('/latest/meta-data/public-hostname')
def handle_public_hostname():
    return "localhost"


@app.route('/latest/meta-data/instance-id')
def handle_instance_id():
    return "i-00000000"


@app.route('/latest/meta-data/placement/availability-zone')
def handle_availability_zone():
    return "us-west-2a"


@app.route('/latest/meta-data/iam/security-credentials/<role_name>')
def handle_security_credentials(role_name):
    """
    Assumes an IAM role and returns the security credentials. Caches results in application context until expiration.
    :param role_name: the IAM role to assume
    """
    with app.app_context():
        credentials = getattr(current_app, '_security_credentials', None)
        expiration = getattr(current_app, '_security_credentials_expiration', None)

        if not credentials or datetime.now(pytz.utc) > expiration:
            role = iam.connect_to_region(REGION).get_role(role_name)
            session = sts.connect_to_region(REGION).assume_role(role.arn, "Local")

            credentials = jsonify({
                "Code": "Success",
                "LastUpdated": datetime.now(pytz.utc).strftime(DATE_FORMAT),
                "Type": "AWS-HMAC",
                "AccessKeyId": session.credentials.access_key,
                "SecretAccessKey": session.credentials.secret_key,
                "Token": session.credentials.session_token,
                "Expiration": session.credentials.expiration
            })

            current_app._security_credentials = credentials
            current_app._security_credentials_expiration = datetime.strptime(session.credentials.expiration,
                                                                             DATE_FORMAT).replace(tzinfo=pytz.utc)

        return credentials


@app.route('/latest/meta-data/iam/security-credentials/')
def handle_role():
    return "engineer"

@app.after_request
def apply_caching(response):
    response.headers["content-type"] = "text/plain"
    return response

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)
