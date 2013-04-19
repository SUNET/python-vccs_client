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
  >>> a = vccs_client.VCCSClient(base_url='http://localhost:8550/')
  >>> a.add_credentials('ft@example.net', [f])
  True
  >>>>

Authenticate with incorrect password :

  >>> a.authenticate('ft@example.net', [f])
  True
  >>> incorrect_f = vccs_client.VCCSPasswordFactor('foobar', credential_id=4712)
  >>> a.authenticate('ft@example.net', [incorrect_f])
  False
  >>>


"""

__version__ = '0.1'
__copyright__ = 'NORDUnet A/S'
__organization__ = 'NORDUnet'
__license__ = 'BSD'
__authors__ = ['Fredrik Thulin']

__all__ = [
    ]


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

    def to_dict(self):
        raise NotImplementedError('Sub-class must implement to_tuple')


class VCCSPasswordFactor(VCCSFactor):

    def __init__(self, plaintext, credential_id, salt=None, log_rounds=12):
        if salt is None:
            salt = bcrypt.gensalt(log_rounds)
        if not salt.startswith('$2a$'):
            raise ValueError('Invalid salt (not bcrypt)')
        self.salt = salt
        self.credential_id = credential_id
        bcrypt_hashed = bcrypt.hashpw(plaintext, salt)
        # withhold bcrypt salt from authentication backends
        self.hash = bcrypt_hashed[len(salt):]
        VCCSFactor.__init__(self)

    def to_dict(self):
        res = {'type': 'password',
               'H1': self.hash,
               'credential_id': self.credential_id,
               }
        return res


class VCCSClient():

    def __init__(self, base_url='http://localhost:8550/'):
        self.base_url = base_url

    def authenticate(self, user_id, factors):
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
        else:
            raise ValueError('Unknown response_label {!r}'.format(response_label))
        values = {'request': data}
        data = urllib.urlencode(values)
        req = urllib2.Request(self.base_url + service, data)
        response = urllib2.urlopen(req)
        body = response.read()

        # parse the response
        resp = json.loads(body)
        if not response_label in resp:
            raise ValueError('Expected {!r} not found in parsed response'.format(response_label))
        resp_ver = resp[response_label]['version']
        if resp_ver != 1:
            raise AssertionError('Received response of unknown version {!r}'.format(resp_ver))
        return resp[response_label]

    def _make_request(self, action, user_id, factors):
        """
        :params action: 'auth' or 'add_creds'
        :params factors: list of VCCSFactor instances
        :returns: request as string (JSON)
        """
        if not action in ['auth', 'add_creds']:
            raise ValueError('Unknown action {!r}'.format(action))
        a = {action:
                 {'version': 1,
                  'user_id': user_id,
                  'factors': [x.to_dict() for x in factors],
                  }
             }
        return json.dumps(a, sort_keys=True, indent=4)
