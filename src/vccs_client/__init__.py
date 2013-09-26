#
# Copyright (c) 2013 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

"""
the VCCS authentication client package

Copyright (c) 2013 NORDUnet A/S
See the source file for complete license statement.


Short usage, see the README for details :

Add credential, and authenticate with correct password :

  >>> import vccs_client
  >>> f = vccs_client.VCCSPasswordFactor('password', credential_id=4712)
  >>> client = vccs_client.VCCSClient(base_url='http://localhost:8550/')
  >>> client.add_credentials('ft@example.net', [f])
  True
  >>> f.salt
  '$2a$12$F0TIdfp4quhVJYIOO1ojU.'
  >>>

The salt and the credential_id needs to be remembered in the client
application for use when validating the password later on.


Authenticate with incorrect password :

  >>> client.authenticate('ft@example.net', [f])
  True
  >>> incorrect_f = vccs_client.VCCSPasswordFactor('foobar', credential_id=4712,
  ...       salt='$2a$12$F0TIdfp4quhVJYIOO1ojU.')
  >>> client.authenticate('ft@example.net', [incorrect_f])
  False
  >>>

Revoke a credential (irreversible!) :

  >>> r = vccs_client.VCCSRevokeFactor(4712, 'testing revoke', reference='foobar')
  >>> client.revoke_credentials('ft@example.net', [r])
  True
  >>>

"""

__version__ = '0.2'
__copyright__ = 'NORDUnet A/S'
__organization__ = 'NORDUnet'
__license__ = 'BSD'
__authors__ = ['Fredrik Thulin']

__all__ = [
    ]


import os
import bcrypt
import urllib
import urllib2
import simplejson as json


class VCCSFactor():
    """
    Base class for authentication factors. Do not use directly.
    """
    def __init__(self):
        pass

    def to_dict(self, _action):
        raise NotImplementedError('Sub-class must implement to_tuple')


class VCCSPasswordFactor(VCCSFactor):
    """
    Object representing an ordinary password authentication factor.
    """

    def __init__(self, plaintext, credential_id, salt=None):
        """
        :params plaintext: string, password as plaintext
        :params credential_id: integer, unique index of credential
        :params salt: string or None, NDNv1H1 salt to be used for pre-hashing
                      (if None, one will be generated. If non-default salt
                      parameters are requested, use generate_salt() directly)
        """

        if salt is None:
            salt = self.generate_salt()
        if not salt.startswith('$NDNv1H1$'):
            raise ValueError('Invalid salt (not NDNv1H1)')
        self.salt = salt
        self.credential_id = credential_id
        salt, key_length, rounds, = self._decode_parameters(salt)
        T1 = "{!s}{!s}{!s}{!s}".format(len(str(credential_id)), str(credential_id), len(plaintext), plaintext)
        self.hash = bcrypt.kdf(T1, salt, key_length, rounds).encode('hex')
        VCCSFactor.__init__(self)

    def generate_salt(self, salt_length=32, desired_key_length=32, rounds=2**5):
        """
        Generate a NDNv1H1 salt.

        Encoded into the salt will be the KDF parameter values desired_key_length
        and rounds.

        For number of rounds, it is recommended that a measurement is made to achieve
        a cost of at least 100 ms on current hardware.

        :params salt_length: Number of bytes of salt to generate (recommended min 16).
        :params desired_key_length: Length of H1 hash to produce (recommended min 32).
        :params rounds: bcrypt pbkdf number of rounds.
        :returns: string with salt and parameters
        """
        salt = os.urandom(salt_length)
        return "$NDNv1H1${!s}${!r}${!r}$".format(salt.encode('hex'), desired_key_length, rounds)

    def _decode_parameters(self, salt):
        """
        Internal function to decode a NDNv1H1 salt.
        """
        _, version, salt, desired_key_length, rounds, _ = salt.split('$')
        if version == 'NDNv1H1':
            return (salt.decode('hex'), int(desired_key_length), int(rounds))
        raise NotImplementedError('Unknown hashing scheme')

    def to_dict(self, _action):
        """
        Return factor as dictionary, transmittable to authentiation backends.
        """
        res = {'type': 'password',
               'H1': self.hash,
               'credential_id': self.credential_id,
               }
        return res


class VCCSOathFactor(VCCSFactor):
    """
    Object representing an OATH token authentication factor.
    """

    def __init__(self, oath_type, credential_id, user_code=None, nonce=None,
                 aead=None, key_handle=None, digits=6, oath_counter=0):
        """
        :params oath_type: 'oath-totp' or 'oath-hotp' (time based or event based OATH)
        :params credential_id: integer, unique index of credential

        for authentication :
        :params user_code: integer, the user supplied token code

        for initialization (add_creds) :
        :params nonce: string, AEAD nonce
        :params aead: string, encrypted OATH secret
        :params key_handle: integer(), YubiHSM key handle used to create AEAD
        :params digits: integer, OATH token number of digits per code (6/8)
        :params oath_counter: initial OATH counter value of token
        """
        if oath_type not in ['oath-totp', 'oath-hotp']:
            raise ValueError('Invalid OATH type (not oath-totp or oath-hotp)')
        self.oath_type = oath_type
        self.credential_id = credential_id
        self.user_code = user_code
        self.nonce = nonce
        self.aead = aead
        self.key_handle = key_handle
        self.digits = digits
        self.oath_counter = oath_counter
        VCCSFactor.__init__(self)

    def to_dict(self, action):
        """
        Return factor as dictionary, transmittable to authentiation backends.
        """
        if action == 'auth':
            if self.user_code is None:
                raise ValueError('User code not provided')
            res = {'type': self.oath_type,
                   'user_code': self.user_code,
                   'credential_id': self.credential_id,
                   }
        elif action == 'add_creds':
            res = {'type': self.oath_type,
                   'credential_id': self.credential_id,
                   'nonce': self.nonce,
                   'aead': self.aead,
                   'key_handle': self.key_handle,
                   'digits': self.digits,
                   'oath_counter': self.oath_counter,
                   }
        else:
            raise ValueError('Unknown \'action\' value (not auth or add_creds)')
        for (k, v) in res.items():
            if v is None:
                raise ValueError('{!r} property {!r} not provided'.format(action, k))
        return res


class VCCSRevokeFactor(VCCSFactor):
    """
    Object representing a factor to be revoked.
    """

    def __init__(self, credential_id, reason, reference=''):
        """
        :params credential_id: integer, unique index of credential
        :params reason: string, reason for revocation
        :params reference: string, optional data to identify this event in logs on frontend
        """

        if not isinstance(reason, basestring):
            raise TypeError('Revocation reason value type error : {!r}'.format(reason))
        if not isinstance(reference, basestring):
            raise TypeError('Revocation reference value type error : {!r}'.format(reference))

        self.credential_id = credential_id
        self.reason = reason
        self.reference = reference
        VCCSFactor.__init__(self)

    def to_dict(self, _action):
        """
        Return factor as dictionary, transmittable to authentiation backends.
        """
        res = {'credential_id': self.credential_id,
               'reason': self.reason,
               'reference': self.reference,
               }
        return res


class VCCSClient():

    def __init__(self, base_url='http://localhost:8550/'):
        self.base_url = base_url

    def authenticate(self, user_id, factors):
        """
        Make an authentication request for one or more factors belonging to a certain user.

        The backend is intentionally secret about details for failures, and will in fact
        return a HTTP error for many errors. The only thing that is for certain is that
        if this function returns True, the backend considers the user properly authenticated
        based on the provided factors.

        :params user_id: persistent user identifier as string
        :params factors: list of VCCSFactor() instances
        :returns: boolean, success or not
        """
        auth_req = self._make_request('auth', user_id, factors)

        response = self._execute(auth_req, 'auth_response')
        resp_auth = response['authenticated']
        if type(resp_auth) != bool:
            raise TypeError('Authenticated value type error : {!r}'.format(resp_auth))
        return resp_auth == True

    def add_credentials(self, user_id, factors):
        """
        Ask the authentication backend to add one or more credentials to it's
        private credential store.

        :params user_id: persistent user identifier as string
        :params factors: list of VCCSFactor() instances
        :returns: boolean, success or not
        """
        add_creds_req = self._make_request('add_creds', user_id, factors)

        response = self._execute(add_creds_req, 'add_creds_response')
        success = response['success']
        if type(success) != bool:
            raise TypeError('Operation success value type error : {!r}'.format(success))
        return success == True

    def revoke_credentials(self, user_id, factors):
        """
        Ask the authentication backend to revoke one or more credentials in it's
        private credential store.

        :params user_id: persistent user identifier as string
        :params factors: list of VCCSRevokeFactor() instances
        :returns: boolean, success or not
        """
        revoke_creds_req = self._make_request('revoke_creds', user_id, factors)

        response = self._execute(revoke_creds_req, 'revoke_creds_response')
        success = response['success']
        if type(success) != bool:
            raise TypeError('Operation success value type error : {!r}'.format(success))
        return success == True

    def _execute(self, data, response_label):
        """
        Make a HTTP POST request to the authentication backend, and parse the result.

        :params data: request as string (JSON)
        :params response_label: 'auth_response' or 'add_creds_response'
        :returns: data from response identified by key response_label - supposedly a dict
        """
        # make the request
        if response_label == 'auth_response':
            service = 'authenticate'
        elif response_label == 'add_creds_response':
            service = 'add_creds'
        elif response_label == 'revoke_creds_response':
            service = 'revoke_creds'
        else:
            raise ValueError('Unknown response_label {!r}'.format(response_label))
        values = {'request': data}
        body = self._execute_request_response(service, values)

        # parse the response
        resp = json.loads(body)
        if not response_label in resp:
            raise ValueError('Expected {!r} not found in parsed response'.format(response_label))
        resp_ver = resp[response_label]['version']
        if resp_ver != 1:
            raise AssertionError('Received response of unknown version {!r}'.format(resp_ver))
        return resp[response_label]

    def _execute_request_response(self, service, values):
        """
        The part of _execute that has actual side effects. In a separate function
        to make everything else easily testable.
        """
        data = urllib.urlencode(values)
        req = urllib2.Request(self.base_url + service, data)
        response = urllib2.urlopen(req)
        return response.read()

    def _make_request(self, action, user_id, factors):
        """
        :params action: 'auth', 'add_creds' or 'revoke_creds'
        :params factors: list of VCCSFactor instances
        :returns: request as string (JSON)
        """
        if not action in ['auth', 'add_creds', 'revoke_creds']:
            raise ValueError('Unknown action {!r}'.format(action))
        a = {action:
                 {'version': 1,
                  'user_id': user_id,
                  'factors': [x.to_dict(action) for x in factors],
                  }
             }
        return json.dumps(a, sort_keys=True, indent=4)
