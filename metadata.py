from datetime import datetime

from flask import Flask, abort, jsonify, current_app
from boto import sts, iam
import pytz

app = Flask(__name__)

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
REGION = "us-west-2"


@app.route('/latest/meta-data')
def handle_root():
    """
    Returns the root metadata keys.
    """
    return "\n".join(sorted(metadata().keys()))


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


@app.route('/latest/meta-data/<path>')
def handle_metadata(path):
    """
    Walks the metadata dictionary for a value. Returns 404 if None is returned.
    :param path: a metadata path
    """
    item = walk(path.split('/'), metadata())
    if item:
        return item
    else:
        abort(404)


def walk(tokens, data):
    """
    Iterates over a list of keys and walks a tree of dictionaries by until a leaf is found.
    :param tokens: a list of tokens
    :param data: a dictionary tree
    :return: None or a leave of the tree
    """
    item = data.get(tokens[0])
    if not item:
        return None
    elif isinstance(item, dict):
        walk(tokens[1:], item)
    else:
        return item


def metadata():
    with app.app_context():
        return getattr(current_app, '_metadata', dict())


if __name__ == '__main__':
    import sys
    import json

    with app.app_context():
        current_app._metadata = dict()
        if len(sys.argv) > 1:
            try:
                with open(sys.argv[1], 'rb') as f:
                    current_app._metadata = json.load(f)
            except IOError as e:
                print sys.exit("missing configuration file")

    app.run(debug=True, host='0.0.0.0', port=80)