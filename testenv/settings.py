# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import saml2.xmldsig as ds
from saml2.samlp import STATUS_AUTHN_FAILED

ALLOWED_SIG_ALGS = [
    ds.SIG_RSA_SHA256,
    ds.SIG_RSA_SHA384,
    ds.SIG_RSA_SHA512,
    ds.SIG_RSA_RIPEMD160,
]

COMPARISONS = ['exact', 'minimum', 'better', 'maximum']

SPID_LEVELS = [
    'https://www.spid.gov.it/SpidL1',
    'https://www.spid.gov.it/SpidL2',
    'https://www.spid.gov.it/SpidL3'
]

AUTH_FAILED_ATTEMPTS = 19
AUTH_WRONG_SPID_LEVEL = 20
AUTH_TIMEOUT = 21
AUTH_NO_CONSENT = 22
AUTH_BLOCKED_CREDENTIALS = 23

SPID_ERRORS = {
    AUTH_FAILED_ATTEMPTS: STATUS_AUTHN_FAILED,
    AUTH_WRONG_SPID_LEVEL: STATUS_AUTHN_FAILED,
    AUTH_TIMEOUT: STATUS_AUTHN_FAILED,
    AUTH_NO_CONSENT: STATUS_AUTHN_FAILED,
    AUTH_BLOCKED_CREDENTIALS: STATUS_AUTHN_FAILED
}

TIMEDELTA = 2
SIGN_ALG = ds.SIG_RSA_SHA512
DIGEST_ALG = ds.DIGEST_SHA512

XML_SCHEMAS = {
    'protocol': 'saml-schema-protocol-2.0.xsd',
}

spid_error_table = '''
<html>
<head>
<script src="https://code.jquery.com/jquery-3.3.1.js"></script>
</head>
<body>
    <div id="message">
        {% for line in lines %}
            <pre class="xml-line">{{line}}</pre>
        {% endfor %}
    </div>
    <table class="spid-error" border=1>
        <thead>
            <tr>
                <th>Elemento</th>
                <th>Dettagli errore</th>
            </tr>
        </thead>
        <tbody>
            {% for err in errors %}
                <tr>
                    <td class="spid-error__elem" id="{{err.1}}">{{err.1}}</td>
                    <td>
                    <ul>
                        {% for name, msgs in err.2.items() %}
                            <li>{{name}}
                                <ul>
                                {% if msgs is mapping %}
                                    {% for type, msg in msgs.items() %}
                                        <li>{{msg|safe}}</li>
                                    {% endfor %}
                                {% else %}
                                    <li>{{msgs}}</li>
                                {% endif %}
                                </ul>
                            </li>
                        {% endfor %}
                    </ul>
                    </td>
                </tr>
            {% endfor %}
        </tbody>
    </table>

<script type="text/javascript">
    $(document).ready(function(){
        $.each($('.spid-error__elem'), function(){
            var id = $(this).attr('id');
            var line = $('.xml-line:contains("<' + id + '")');
            var tag = line[0];
            $(tag).css('background-color', 'red');
        });
    });
</script>
</body>
</html>
'''
