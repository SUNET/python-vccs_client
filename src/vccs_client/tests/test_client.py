#!/usr/bin/python
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
Test VCCS client.
"""

import os
import unittest

import vccs_client

class TestVCCSClient(unittest.TestCase):

    def test_password_factor(self):
        """
        Test creating a VCCSPasswordFactor instance.
        """
        f = vccs_client.VCCSPasswordFactor('password', 4711, '$2a$08$Ahy51oCM6Vg6d.1ScOPxse')
        self.assertEqual(f.to_dict('auth'),
                         {'type': 'password',
                          'credential_id': 4711,
                          'H1': '8A5TOXW92nt0AYKipKvn2brhEyCdsT.',
                          }
                         )

    def test_OATH_factor_auth(self):
        """
        Test creating a VCCSOathFactor instance.
        """
        aead = 'aa' * 20
        o = vccs_client.VCCSOathFactor('oath-hotp', 4712, nonce='010203040506', aead=aead, user_code='123456')
        self.assertEqual(o.to_dict('auth'),
                         {'type': 'oath-hotp',
                          'credential_id': 4712,
                          'user_code': '123456',
                          }
                         )

    def test_OATH_factor_add(self):
        """
        Test creating a VCCSOathFactor instance for an add_creds request.
        """
        aead = 'aa' * 20
        o = vccs_client.VCCSOathFactor('oath-hotp', 4712, nonce='010203040506', aead=aead)
        self.assertEqual(o.to_dict('add_creds'),
                         {'aead': aead,
                          'credential_id': 4712,
                          'digits': 6,
                          'nonce': '010203040506',
                          'oath_counter': 0,
                          'type': 'oath-hotp',
                          }
                         )

    def test_missing_parts_of_OATH_factor(self):
        """
        Test creating a VCCSOathFactor instance with missing parts.
        """
        aead = 'aa' * 20
        o = vccs_client.VCCSOathFactor('oath-hotp', 4712, user_code='123456')
        # missing AEAD
        with self.assertRaises(ValueError):
            o.to_dict('add_creds')

        o = vccs_client.VCCSOathFactor('oath-hotp', 4712, nonce='010203040506', aead=aead, user_code='123456')
        # with AEAD o should be OK
        self.assertEquals(type(o.to_dict('add_creds')), dict)
        # unknown to_dict 'action' should raise
        with self.assertRaises(ValueError):
            o.to_dict('bad_action')
