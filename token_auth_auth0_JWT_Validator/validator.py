from urllib.request import urlopen, HTTPError
import json
from authlib.jose.rfc7517.jwk import JsonWebKey
from authlib.oauth2.rfc7523 import JWTBearerTokenValidator
from authlib.jose.rfc7517.jwk import JsonWebKey

class Auth0JWTBearerTokenValidator(JWTBearerTokenValidator):
    def __init__(self, domain, audience):
        issuer = f"https://{domain}/"
        jwks_url = f"{issuer}.well-known/jwks.json"
        try:
            with urlopen(jwks_url) as response:
                jwks_data = response.read()
                print("Fetched JWKS JSON data successfully.")
        except HTTPError as e:
            print(f"Failed to fetch JWKS JSON data: {e}")
            raise 

        try:
            jwks = json.loads(jwks_data)
            print(f"JWKS - \n{jwks}")
            public_key = JsonWebKey.import_key_set(jwks)
            print("Imported public key from JWKS successfully.")
        except json.JSONDecodeError as e:
            print(f"Failed to parse JWKS JSON data: {e}")
            raise 
        except Exception as e:
            print(f"Failed to import public key from JWKS: {e}")
            raise  

        super(Auth0JWTBearerTokenValidator, self).__init__(public_key)

        self.claims_options = {
            "exp": {"essential": True},
            "aud": {"essential": True, "value": audience},
            "iss": {"essential": True, "value": issuer},
        }

        print("Auth0JWTBearerTokenValidator initialized with:")
        print(f"- Issuer: {issuer}")
        print(f"- Audience: {audience}")
        print(f"- Claims Options: {self.claims_options}")
        print(f"- Public Key: {public_key}")

