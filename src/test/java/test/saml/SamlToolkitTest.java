package test.saml;

import org.testng.Assert;
import org.testng.annotations.Test;
import test.saml2.SamlToolkit;

import java.io.UnsupportedEncodingException;

public class SamlToolkitTest {
    String redirectSAML_Payload = "fZJRb9sgFIXf9yss3rGB2Aqg2FW2qlqlTosadw97iQBfp0g2ZICj%2Ffw5TqtmL31BIA7fufceNnd%2FxyE7Q4jWuxrRnKAMnPGddccavbQPmKO75ssmqnFgJ7md0qt7hj8TxJRtY4SQ5nffvIvTCGEP4WwNvDw%2F1eg1pVOURRGjxx2c85M6QvDeDdZBbvxYqAtqWcEla9QFVJgA8%2BYMB9UdLpaHm3sfUHY%2F%2B1q3aD8sBn%2B0Lh%2BtCT76Pt14mH5Ftep6rAVQXBLdYaWMwFQZrqFThPFVsbSGsgcfDCz91SiFCVD2eF%2BjA%2B00FwQ0rqp%2BRnSsx0KVCgteVSU3DDTXszTGCR5dTMqlGjHCCCZrTNct4bJisuS5oOI3ynbBJ2%2F88NW664Sn4KRX0Ubp1AhRJiP32x9PkuVE6qsoyu9tu8O7n%2FsWZb%2Fek2KXpObsXJTXbD5nnd6MUXONUi4Vh1vC5wD1HjZqaNmzqlsRbED3uCz7cp4GM5itqSGCMkLWYlPc2jRvx%2F8%2FUPMP";
    String postSAML_Payload = "PHNhbWxwOlJlc3BvbnNlIElEPSJfODAwZTU2OTItMDZlNS00ZjBjLTg5MTMtNGY1NmU5MWVkYWY3IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyMC0wNy0xN1QwODo1MzoyOC40NjlaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9zc28tZGV2LnBhZ2Vyb29ubGluZS5jb20vYXV0aG4vYXV0aGVudGljYXRpb24vY3JlYXRpdmVfYWRfc2FtbF9hdXRoZW50aWNhdG9yIiBJblJlc3BvbnNlVG89Il8xZGI4OTBlYi01NWYxLTRkMmYtOWE0YS05ODU1NDhjMmViOGIiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2NmMzFiYWRmLWI5ZTEtNDBiZC1hYWM5LTFhYzhiZWRhMDI4My88L0lzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48QXNzZXJ0aW9uIElEPSJfNTRiZTA2MDgtYTg1MC00Y2E4LWFiYzUtMjM4YTVhNzQwMjAzIiBJc3N1ZUluc3RhbnQ9IjIwMjAtMDctMTdUMDg6NTM6MjguNDY5WiIgVmVyc2lvbj0iMi4wIiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI";

    String redirectSAML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<saml2p:AuthnRequest AssertionConsumerServiceURL=\"https://sso-dev.pageroonline.com/authn/authentication/creative_ad_saml_authenticator\" Destination=\"https://login.microsoftonline.com/cf31badf-b9e1-40bd-aac9-1ac8beda0283/saml2\" ForceAuthn=\"true\" ID=\"_1db890eb-55f1-4d2f-9a4a-985548c2eb8b\" IssueInstant=\"2020-07-17T08:52:48.919Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">14f25d30-cebf-44f4-982c-271c09120079</saml2:Issuer></saml2p:AuthnRequest>";
    String postSAML = "<samlp:Response ID=\"_800e5692-06e5-4f0c-8913-4f56e91edaf7\" Version=\"2.0\" IssueInstant=\"2020-07-17T08:53:28.469Z\" Destination=\"https://sso-dev.pageroonline.com/authn/authentication/creative_ad_saml_authenticator\" InResponseTo=\"_1db890eb-55f1-4d2f-9a4a-985548c2eb8b\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://sts.windows.net/cf31badf-b9e1-40bd-aac9-1ac8beda0283/</Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status><Assertion ID=\"_54be0608-a850-4ca8-abc5-238a5a740203\" IssueInstant=\"2020-07-17T08:53:28.469Z\" Version=\"2.0\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"";


    @Test
    public void testPost_SAML_decode() throws Exception {
        String saml = SamlToolkit.decodeSAML_POST(postSAML_Payload);
        Assert.assertEquals(saml, postSAML);
    }

    @Test
    public void testRedirectSAML_decode() throws Exception {
        String saml = SamlToolkit.decodeSAML_redirect(redirectSAML_Payload);
        Assert.assertEquals(saml, redirectSAML);
    }
}
