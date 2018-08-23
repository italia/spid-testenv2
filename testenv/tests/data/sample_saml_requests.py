valid = [

    """\
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24" Version="2.0" ProviderName="SP test" IssueInstant="2014-07-16T23:52:45Z" Destination="http://idp.example.com/SSOService.php" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://sp.example.com/demo1/index.php?acs">
    <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>""",

    """\
<saml2p:AuthnRequest IssueInstant="2018-06-28T15:49:38Z" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="1" Destination="http://localhost:8088/sso" ID="a0a50e3ee82ecb44365a0b4bec0374e0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="https://localhost/">https://localhost/</saml2:Issuer>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"></saml2p:NameIDPolicy>
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>""",

    """\
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx41d8ef22-e612-8c50-9960-1b16f15741b3" Version="2.0" ProviderName="SP test" IssueInstant="2014-07-16T23:52:45Z" Destination="http://idp.example.com/SSOService.php" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://sp.example.com/demo1/index.php?acs">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#pfx41d8ef22-e612-8c50-9960-1b16f15741b3">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>yJN6cXUwQxTmMEsPesBP2NkqYFI=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>g5eM9yPnKsmmE/Kh2qS7nfK8HoF6yHrAdNQxh70kh8pRI4KaNbYNOL9sF8F57Yd+jO6iNga8nnbwhbATKGXIZOJJSugXGAMRyZsj/rqngwTJk5KmujbqouR1SLFsbo7Iuwze933EgefBbAE4JRI7V2aD9YgmB3socPqAi2Qf97E=</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQQFADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcwMDI5MjdaFw0xNTA3MTcwMDI5MjdaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7vU/6R/OBA6BKsZH4L2bIQ2cqBO7/aMfPjUPJPSn59d/f0aRqSC58YYrPuQODydUABiCknOn9yV0fEYm4bNvfjroTEd8bDlqo5oAXAUAI8XHPppJNz7pxbhZW0u35q45PJzGM9nCv9bglDQYJLby1ZUdHsSiDIpMbGgf/ZrxqawIDAQABo1AwTjAdBgNVHQ4EFgQU3s2NEpYx7wH6bq7xJFKa46jBDf4wHwYDVR0jBBgwFoAU3s2NEpYx7wH6bq7xJFKa46jBDf4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQQFAAOBgQCPsNO2FG+zmk5miXEswAs30E14rBJpe/64FBpM1rPzOleexvMgZlr0/smF3P5TWb7H8Fy5kEiByxMjaQmml/nQx6qgVVzdhaTANpIE1ywEzVJlhdvw4hmRuEKYqTaFMLez0sRL79LUeDxPWw7Mj9FkpRYT+kAGiFomHop1nErV6Q==</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>""",

]

invalid_id_attr = """\
<saml2p:AuthnRequest Destination="http://localhost:8088/sso" IssueInstant="2018-07-19T11:29:49Z" ID="23e77ad3a97ce0e5f04e610e3b391a44" ForceAuthn="false" AssertionConsumerServiceURL="http://localhost:3000/spid-sso" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0" AttributeConsumingServiceIndex="0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="https://localhost/">https://localhost/</saml2:Issuer>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"></saml2p:NameIDPolicy>
    <saml2p:RequestedAuthnContext Comparison="exact">
        <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>"""

missing_issue_instant_attr = """\
<saml2p:AuthnRequest AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="1" Destination="http://localhost:8088/sso" ID="a0a50e3ee82ecb44365a0b4bec0374e0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="https://localhost/">https://localhost/</saml2:Issuer>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"></saml2p:NameIDPolicy>
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>"""

multiple_errors = """\
<saml2p:AuthnRequest IssueInstant="2018-06-28T15:49:38Z" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="1" Destination="http://localhost:8088/sso" ID="0a" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="https://localhost/">https://localhost/</saml2:Issuer>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"></saml2p:NameIDPolicy>
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>"""

unexpected_element = """\
<saml2p:AuthnRequest IssueInstant="2018-06-28T15:49:38Z" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="1" Destination="http://localhost:8088/sso" ID="a0a50e3ee82ecb44365a0b4bec0374e0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="https://localhost/">https://localhost/</saml2:Issuer>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"></saml2p:NameIDPolicy>
    <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml2:AuthnContextClassRef>
</saml2p:AuthnRequest>"""

invalid_comparison_attr = """\
<saml2p:AuthnRequest IssueInstant="2018-06-28T15:49:38Z" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="1" Destination="http://localhost:8088/sso" ID="a0a50e3ee82ecb44365a0b4bec0374e0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="https://localhost/">https://localhost/</saml2:Issuer>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"></saml2p:NameIDPolicy>
    <saml2p:RequestedAuthnContext Comparison="invalid">
        <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>"""
