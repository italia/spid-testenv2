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
