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

Copyright (c) 2012, 2013 NORDUnet A/S
See the source file for complete license statement.

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

class VCCSAuthenticator():
    def __init__(self, url='http://localhost:8550/authenticate'):
        self.url = url

    def authenticate(self, plaintext, salt, user_id, credential_id):
        if not salt.startswith('$2a$'):
            raise ValueError('Invalid salt (not bcrypt)')
        bcrypt_hashed = bcrypt.hashpw(plaintext, salt)
        # withhold bcrypt salt from authentication backends
        H1 = bcrypt_hashed[len(salt):]

        auth_req = self._make_request('auth', H1, user_id, credential_id)
        values = {'request': auth_req}

        data = urllib.urlencode(values)
        req = urllib2.Request(self.url, data)
        response = urllib2.urlopen(req)
        body = response.read()
        try:
            resp = json.loads(body)
            resp_ver = resp['auth_response']['version']
            if resp_ver != 1:
                raise AssertionError('Received response of unknown version {!r}'.format(resp_ver))
            resp_auth = resp['auth_response']['authenticated']
            if type(resp_auth) != bool:
                raise TypeError('Authenticated value type error : {!r}'.format(resp_auth))
            return resp_auth == True
        except Exception:
            raise

    def _make_request(self, action, H1, user_id, credential_id):
        a = {action:
                 {'version': 1,
                  'user_id': user_id,
                  'factors': [
                    {'type': 'password',
                     'H1': H1,
                     'credential_id': credential_id,
                     }
                    ]
                  }
             }
        return json.dumps(a, sort_keys=True, indent=4)
