import os

import requests
from requests.auth import HTTPBasicAuth

KEYCLOAK_HOST = os.environ.get('KEYCLOAK_HOST')
KEYCLOAK_REALM = os.environ.get('KEYCLOAK_REALM')
KEYCLOAK_SCHEME = os.environ.get('KEYCLOAK_SCHEME', 'https')
KEYCLOAK_CLIENT_ID = os.environ.get('KEYCLOAK_CLIENT_ID')
KEYCLOAK_CLIENT_SECRET = os.environ.get('KEYCLOAK_CLIENT_SECRET')


def get_keycloak_token_introspect_endpoint(host, realm, scheme='https'):
    return f'{scheme}://{host}/auth/realms/{realm}/protocol/openid-connect/token/introspect'


def lambda_handler(event, context):
    introspect_endpoint = get_keycloak_token_introspect_endpoint(
        KEYCLOAK_HOST, KEYCLOAK_REALM, KEYCLOAK_SCHEME
    )
    token = event.get("authorizationToken").split(" ")[1]
    print(event)
    print(f"TOKEN={token}")
    print({
        f"KEYCLOAK_{k}": os.environ.get(f"KEYCLOAK_{k}")
        for k in ["HOST", "REALM", "CLIENT_ID", "CLIENT_SECRET"]
    })

    data = dict(token=token)
    basic = HTTPBasicAuth(KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET)

    resp = requests.post(introspect_endpoint, data=data, auth=basic)
    result = resp.json()
    print(result)

    if not result.get('active'):
        return {}

    return {
        "principalId": result.get('sub'),
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": event.get("methodArn"),
                }
            ],
        },
        "context": {
            "email": result.get("email"),
            "username": result.get("username")
        },
    }
