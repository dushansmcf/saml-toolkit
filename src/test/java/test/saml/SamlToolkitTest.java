package test.saml;

import org.testng.Assert;
import org.testng.annotations.Test;
import test.saml2.SamlToolkit;
import test.saml2.Util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;

public class SamlToolkitTest {
    String redirectSAML_Payload = "fZJRb9sgFIXf9yss3rGB2Aqg2FW2qlqlTosadw97iQBfp0g2ZICj%2Ffw5TqtmL31BIA7fufceNnd%2FxyE7Q4jWuxrRnKAMnPGddccavbQPmKO75ssmqnFgJ7md0qt7hj8TxJRtY4SQ5nffvIvTCGEP4WwNvDw%2F1eg1pVOURRGjxx2c85M6QvDeDdZBbvxYqAtqWcEla9QFVJgA8%2BYMB9UdLpaHm3sfUHY%2F%2B1q3aD8sBn%2B0Lh%2BtCT76Pt14mH5Ftep6rAVQXBLdYaWMwFQZrqFThPFVsbSGsgcfDCz91SiFCVD2eF%2BjA%2B00FwQ0rqp%2BRnSsx0KVCgteVSU3DDTXszTGCR5dTMqlGjHCCCZrTNct4bJisuS5oOI3ynbBJ2%2F88NW664Sn4KRX0Ubp1AhRJiP32x9PkuVE6qsoyu9tu8O7n%2FsWZb%2Fek2KXpObsXJTXbD5nnd6MUXONUi4Vh1vC5wD1HjZqaNmzqlsRbED3uCz7cp4GM5itqSGCMkLWYlPc2jRvx%2F8%2FUPMP";
    String postSAML_Payload = "PHNhbWxwOlJlc3BvbnNlIElEPSJfODAwZTU2OTItMDZlNS00ZjBjLTg5MTMtNGY1NmU5MWVkYWY3IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyMC0wNy0xN1QwODo1MzoyOC40NjlaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9zc28tZGV2LnBhZ2Vyb29ubGluZS5jb20vYXV0aG4vYXV0aGVudGljYXRpb24vY3JlYXRpdmVfYWRfc2FtbF9hdXRoZW50aWNhdG9yIiBJblJlc3BvbnNlVG89Il8xZGI4OTBlYi01NWYxLTRkMmYtOWE0YS05ODU1NDhjMmViOGIiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2NmMzFiYWRmLWI5ZTEtNDBiZC1hYWM5LTFhYzhiZWRhMDI4My88L0lzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48QXNzZXJ0aW9uIElEPSJfNTRiZTA2MDgtYTg1MC00Y2E4LWFiYzUtMjM4YTVhNzQwMjAzIiBJc3N1ZUluc3RhbnQ9IjIwMjAtMDctMTdUMDg6NTM6MjguNDY5WiIgVmVyc2lvbj0iMi4wIiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI%2BPElzc3Vlcj5odHRwczovL3N0cy53aW5kb3dzLm5ldC9jZjMxYmFkZi1iOWUxLTQwYmQtYWFjOS0xYWM4YmVkYTAyODMvPC9Jc3N1ZXI%2BPFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI%2BPFNpZ25lZEluZm8%2BPENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxSZWZlcmVuY2UgVVJJPSIjXzU0YmUwNjA4LWE4NTAtNGNhOC1hYmM1LTIzOGE1YTc0MDIwMyI%2BPFRyYW5zZm9ybXM%2BPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8%2BPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvVHJhbnNmb3Jtcz48RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8%2BPERpZ2VzdFZhbHVlPjFlV3A0R0xMcnFub3RibVFONXlVeEJBVGZHbnpIU0JCbHYwK3Q3bitzcUU9PC9EaWdlc3RWYWx1ZT48L1JlZmVyZW5jZT48L1NpZ25lZEluZm8%2BPFNpZ25hdHVyZVZhbHVlPkMwVmR0bFhUa09GVXhHaW5WZ3lEd0M0ekgyMmJPRVlqUjNnWWVMeFF2R3VwMG5xZkJkaXJFbzR0NzBNaGMzYjRnVS9sOGVRMkVVMkxTTTVNWStZMUlVeDc0VHBvODVzNHhzTUpQQ1RCRlhzR0J4RXRZandGbFltd2JQcC9lVEp5VE8zaDlaRzlteTFkS09IbTVVclJ0MVdET21wL3RrK0Ywa2dsYVVKSitwcnlXTXh1Zm5uZEdha2VrQjN4bm9GWjh3QytuUVFFeGNUOUQvUWNTWHoxMnlvTXhpUUVYNjNBZ0NQYlBEeFBxNnBwbW5mMlpmZFRkNStkVFZtK1pPMElPckxsSXJiZWZXRFc4K0JIY0Ezbm5SYzg2a1ZFSnN3NkdnVUh5VXMzVm9POWJtcElPTUdHZFcvYm1Ed2I3V0l5cG5IZEMrRjRTdWNueXg0MjdOcHlndz09PC9TaWduYXR1cmVWYWx1ZT48S2V5SW5mbz48WDUwOURhdGE%2BPFg1MDlDZXJ0aWZpY2F0ZT5NSUlEQlRDQ0FlMmdBd0lCQWdJUVBDeEZieVNWU0xaT2dnZVdSekJXT2pBTkJna3Foa2lHOXcwQkFRc0ZBREF0TVNzd0tRWURWUVFERXlKaFkyTnZkVzUwY3k1aFkyTmxjM05qYjI1MGNtOXNMbmRwYm1SdmQzTXVibVYwTUI0WERUSXdNRFl3TnpBd01EQXdNRm9YRFRJMU1EWXdOekF3TURBd01Gb3dMVEVyTUNrR0ExVUVBeE1pWVdOamIzVnVkSE11WVdOalpYTnpZMjl1ZEhKdmJDNTNhVzVrYjNkekxtNWxkRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFPcFpYU3B1VVhQN3pDbXRVVFAwN1ZMOTdaclkrZHNDMGF5YXJ0ZDhoak4vNGRIY0s3dG1UK2Q4dXVjQTM4K3Y3U3dvNkdMa1FybGJJNkZ0Ky90TTExRGtTYjJkQy9kQWdGL3VmSlZ1elhCT0d3TXdOYVY3KzZFZlpFTU5GL0hhZEdyVk9CNXgzbWsxUEMyY1hJeVR1L2Z4L1hNWU1Hdm5KU254c1paWEtMUEU3THJxelBNWXRuY2VWYXNNNmpUQWRyT3RwZHpFemV3TTNMUjFJa0FvbDlvaVFLeG93SWJQcHNVdGNKc2pDTWprb3FYYUhZWTBGa1FITEhsdm1oVmNrVXhWWXZLSkpkbkU5UnlZejEzY2RHOVZxbUVqczNrWGE2eTFIQU5LRWRrODZlOGN6bUNXVWhqWnpTMEttdlgrb2VvZWRsMjE5SWdJTVNvQkE1VWFXeWNDQXdFQUFhTWhNQjh3SFFZRFZSME9CQllFRkZYUDBPREZoamYzUlM2b1Jpak01VGIreUI4Q01BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQjlHdFZpa0xUYkpXSXU1eDlZQ1VUVEt6TmhpNDRYWG9nUC92OFZ5bFJTVUhJNVlUTWRuV3d2REl0L1kxc2pOb25tU3k5UHJpb0VqY0lpSTFVOG5pY3ZlYWZNd0lxNVZMbitnRVkybGc2S0RKQXpnQXZBODhDWHF3ZkhIdnRtWUJvdk43Z29vbHA4VFkva2RkTVRmNlRwTnpOM2xDVE0yTUs0WWU1eExMVkdkcDRicVdDT0ovcWp3RHhwVFJTeWRZSWtMVUR3cU5qditzWWZPRWxKcFlBQjRyVEwvYXczQ2hKMWlhQTRNdFhFdDZPamJVdGJPYTIxbFNoZkx6dk5SYllLMyt1a2JyaG1SbDlsZW1KRWVVbHM1MXZQdUllK2pnK1NzcDQzYXc3UFFqeHQ0L01wZk5NUzJCZlo1RjhHVlNWRzdxTmIzNTJjTExlSmc1cmMzOThaPC9YNTA5Q2VydGlmaWNhdGU%2BPC9YNTA5RGF0YT48L0tleUluZm8%2BPC9TaWduYXR1cmU%2BPFN1YmplY3Q%2BPE5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiPm42YnNLS3l5T2FwWXBIRXFxVkwwZG11RU5hc2paSmhoS1l6eTdPRWVBZW88L05hbWVJRD48U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89Il8xZGI4OTBlYi01NWYxLTRkMmYtOWE0YS05ODU1NDhjMmViOGIiIE5vdE9uT3JBZnRlcj0iMjAyMC0wNy0xN1QwOTo1MzoyOC4zOTFaIiBSZWNpcGllbnQ9Imh0dHBzOi8vc3NvLWRldi5wYWdlcm9vbmxpbmUuY29tL2F1dGhuL2F1dGhlbnRpY2F0aW9uL2NyZWF0aXZlX2FkX3NhbWxfYXV0aGVudGljYXRvciIvPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q%2BPENvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDIwLTA3LTE3VDA4OjQ4OjI4LjM5MVoiIE5vdE9uT3JBZnRlcj0iMjAyMC0wNy0xN1QwOTo1MzoyOC4zOTFaIj48QXVkaWVuY2VSZXN0cmljdGlvbj48QXVkaWVuY2U%2Bc3BuOjE0ZjI1ZDMwLWNlYmYtNDRmNC05ODJjLTI3MWMwOTEyMDA3OTwvQXVkaWVuY2U%2BPC9BdWRpZW5jZVJlc3RyaWN0aW9uPjwvQ29uZGl0aW9ucz48QXR0cmlidXRlU3RhdGVtZW50PjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvdGVuYW50aWQiPjxBdHRyaWJ1dGVWYWx1ZT5jZjMxYmFkZi1iOWUxLTQwYmQtYWFjOS0xYWM4YmVkYTAyODM8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvb2JqZWN0aWRlbnRpZmllciI%2BPEF0dHJpYnV0ZVZhbHVlPmQ3OGEwZDc1LWVmNjktNDVhMi04ZmIyLTY0NzQ2ZTViNjFkYzwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIj48QXR0cmlidXRlVmFsdWU%2BU2FqaXRoLlNAQ3JlYXRpdmVTb2Z0d2FyZS5jb208L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvc3VybmFtZSI%2BPEF0dHJpYnV0ZVZhbHVlPlNpbHZhPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2dpdmVubmFtZSI%2BPEF0dHJpYnV0ZVZhbHVlPlNhaml0aDwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9kaXNwbGF5bmFtZSI%2BPEF0dHJpYnV0ZVZhbHVlPlNhaml0aCBTaWx2YTwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9pZGVudGl0eXByb3ZpZGVyIj48QXR0cmlidXRlVmFsdWU%2BaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvY2YzMWJhZGYtYjllMS00MGJkLWFhYzktMWFjOGJlZGEwMjgzLzwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2NsYWltcy9hdXRobm1ldGhvZHNyZWZlcmVuY2VzIj48QXR0cmlidXRlVmFsdWU%2BaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2F1dGhlbnRpY2F0aW9ubWV0aG9kL3Bhc3N3b3JkPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48L0F0dHJpYnV0ZVN0YXRlbWVudD48QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDIwLTA3LTE3VDA4OjUzOjIyLjc5MVoiIFNlc3Npb25JbmRleD0iXzU0YmUwNjA4LWE4NTAtNGNhOC1hYmM1LTIzOGE1YTc0MDIwMyI%2BPEF1dGhuQ29udGV4dD48QXV0aG5Db250ZXh0Q2xhc3NSZWY%2BdXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQ8L0F1dGhuQ29udGV4dENsYXNzUmVmPjwvQXV0aG5Db250ZXh0PjwvQXV0aG5TdGF0ZW1lbnQ%2BPC9Bc3NlcnRpb24%2BPC9zYW1scDpSZXNwb25zZT4%3D";

    String redirectSAML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<saml2p:AuthnRequest AssertionConsumerServiceURL=\"https://sso-dev.pageroonline.com/authn/authentication/creative_ad_saml_authenticator\" Destination=\"https://login.microsoftonline.com/cf31badf-b9e1-40bd-aac9-1ac8beda0283/saml2\" ForceAuthn=\"true\" ID=\"_1db890eb-55f1-4d2f-9a4a-985548c2eb8b\" IssueInstant=\"2020-07-17T08:52:48.919Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">14f25d30-cebf-44f4-982c-271c09120079</saml2:Issuer></saml2p:AuthnRequest>";
    String postSAML = "<samlp:Response ID=\"_800e5692-06e5-4f0c-8913-4f56e91edaf7\" Version=\"2.0\" IssueInstant=\"2020-07-17T08:53:28.469Z\" Destination=\"https://sso-dev.pageroonline.com/authn/authentication/creative_ad_saml_authenticator\" InResponseTo=\"_1db890eb-55f1-4d2f-9a4a-985548c2eb8b\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://sts.windows.net/cf31badf-b9e1-40bd-aac9-1ac8beda0283/</Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status><Assertion ID=\"_54be0608-a850-4ca8-abc5-238a5a740203\" IssueInstant=\"2020-07-17T08:53:28.469Z\" Version=\"2.0\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"><Issuer>https://sts.windows.net/cf31badf-b9e1-40bd-aac9-1ac8beda0283/</Issuer><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_54be0608-a850-4ca8-abc5-238a5a740203\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>1eWp4GLLrqnotbmQN5yUxBATfGnzHSBBlv0+t7n+sqE=</DigestValue></Reference></SignedInfo><SignatureValue>C0VdtlXTkOFUxGinVgyDwC4zH22bOEYjR3gYeLxQvGup0nqfBdirEo4t70Mhc3b4gU/l8eQ2EU2LSM5MY+Y1IUx74Tpo85s4xsMJPCTBFXsGBxEtYjwFlYmwbPp/eTJyTO3h9ZG9my1dKOHm5UrRt1WDOmp/tk+F0kglaUJJ+pryWMxufnndGakekB3xnoFZ8wC+nQQExcT9D/QcSXz12yoMxiQEX63AgCPbPDxPq6ppmnf2ZfdTd5+dTVm+ZO0IOrLlIrbefWDW8+BHcA3nnRc86kVEJsw6GgUHyUs3VoO9bmpIOMGGdW/bmDwb7WIypnHdC+F4Sucnyx427Npygw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQPCxFbySVSLZOggeWRzBWOjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIwMDYwNzAwMDAwMFoXDTI1MDYwNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOpZXSpuUXP7zCmtUTP07VL97ZrY+dsC0ayartd8hjN/4dHcK7tmT+d8uucA38+v7Swo6GLkQrlbI6Ft+/tM11DkSb2dC/dAgF/ufJVuzXBOGwMwNaV7+6EfZEMNF/HadGrVOB5x3mk1PC2cXIyTu/fx/XMYMGvnJSnxsZZXKLPE7LrqzPMYtnceVasM6jTAdrOtpdzEzewM3LR1IkAol9oiQKxowIbPpsUtcJsjCMjkoqXaHYY0FkQHLHlvmhVckUxVYvKJJdnE9RyYz13cdG9VqmEjs3kXa6y1HANKEdk86e8czmCWUhjZzS0KmvX+oeoedl219IgIMSoBA5UaWycCAwEAAaMhMB8wHQYDVR0OBBYEFFXP0ODFhjf3RS6oRijM5Tb+yB8CMA0GCSqGSIb3DQEBCwUAA4IBAQB9GtVikLTbJWIu5x9YCUTTKzNhi44XXogP/v8VylRSUHI5YTMdnWwvDIt/Y1sjNonmSy9PrioEjcIiI1U8nicveafMwIq5VLn+gEY2lg6KDJAzgAvA88CXqwfHHvtmYBovN7goolp8TY/kddMTf6TpNzN3lCTM2MK4Ye5xLLVGdp4bqWCOJ/qjwDxpTRSydYIkLUDwqNjv+sYfOElJpYAB4rTL/aw3ChJ1iaA4MtXEt6OjbUtbOa21lShfLzvNRbYK3+ukbrhmRl9lemJEeUls51vPuIe+jg+Ssp43aw7PQjxt4/MpfNMS2BfZ5F8GVSVG7qNb352cLLeJg5rc398Z</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">n6bsKKyyOapYpHEqqVL0dmuENasjZJhhKYzy7OEeAeo</NameID><SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><SubjectConfirmationData InResponseTo=\"_1db890eb-55f1-4d2f-9a4a-985548c2eb8b\" NotOnOrAfter=\"2020-07-17T09:53:28.391Z\" Recipient=\"https://sso-dev.pageroonline.com/authn/authentication/creative_ad_saml_authenticator\"/></SubjectConfirmation></Subject><Conditions NotBefore=\"2020-07-17T08:48:28.391Z\" NotOnOrAfter=\"2020-07-17T09:53:28.391Z\"><AudienceRestriction><Audience>spn:14f25d30-cebf-44f4-982c-271c09120079</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name=\"http://schemas.microsoft.com/identity/claims/tenantid\"><AttributeValue>cf31badf-b9e1-40bd-aac9-1ac8beda0283</AttributeValue></Attribute><Attribute Name=\"http://schemas.microsoft.com/identity/claims/objectidentifier\"><AttributeValue>d78a0d75-ef69-45a2-8fb2-64746e5b61dc</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\"><AttributeValue>Sajith.S@CreativeSoftware.com</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname\"><AttributeValue>Silva</AttributeValue></Attribute><Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname\"><AttributeValue>Sajith</AttributeValue></Attribute><Attribute Name=\"http://schemas.microsoft.com/identity/claims/displayname\"><AttributeValue>Sajith Silva</AttributeValue></Attribute><Attribute Name=\"http://schemas.microsoft.com/identity/claims/identityprovider\"><AttributeValue>https://sts.windows.net/cf31badf-b9e1-40bd-aac9-1ac8beda0283/</AttributeValue></Attribute><Attribute Name=\"http://schemas.microsoft.com/claims/authnmethodsreferences\"><AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant=\"2020-07-17T08:53:22.791Z\" SessionIndex=\"_54be0608-a850-4ca8-abc5-238a5a740203\"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></samlp:Response>";

    @Test
    public void testEncodeAndThenDecode() throws Exception {
        byte[] deflated = Util.deflate(redirectSAML.getBytes("utf-8"));
        byte[] b64enc = Base64.getEncoder().encode(deflated);
        System.out.println(new String(b64enc, "utf-8"));
        String uenc = URLEncoder.encode(new String(b64enc, "utf-8"), "utf-8");
        System.out.println(uenc);
        System.out.println(SamlToolkit.decodeSAML_redirect(uenc, true));
    }

    @Test
    public void testPost_SAML_decode() throws Exception {
        String saml = SamlToolkit.decodeSAML_POST(postSAML_Payload);
        Assert.assertEquals(saml, postSAML);
    }

    @Test
    public void testRedirectSAML_decode() throws Exception {
        String saml = SamlToolkit.decodeSAML_redirect(redirectSAML_Payload, true);
        Assert.assertEquals(saml, redirectSAML);
    }


    @Test
    public void test_encode_SAML_redirect() throws Exception {
        String data = SamlToolkit.encodeSAML_redirect(redirectSAML);
        Assert.assertEquals(data, redirectSAML_Payload);
    }

    @Test
    public void test_encode_SAML_post() throws Exception {
        String postSAML="<samlp:Response ID=\"_46db7dd2-4934-4747-8e40-66bbd4535ab6\" Version=\"2.0\" IssueInstant=\"2020-07-27T06:23:53.527Z\"\n" +
                "                Destination=\"https://sso-dev.pageroonline.com/authn/authentication/creative_ad_saml_authenticator\"\n" +
                "                InResponseTo=\"_db478146-73a9-4618-9f78-512463995100\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                "    <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                "        https://sts.windows.net/cf31badf-b9e1-40bd-aac9-1ac8beda0283/\n" +
                "    </Issuer>\n" +
                "    <samlp:Status>\n" +
                "        <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" +
                "    </samlp:Status>\n" +
                "    <Assertion ID=\"_e0a4340f-29ac-49b9-8da0-9b22cb02d300\" IssueInstant=\"2020-07-27T06:23:53.527Z\" Version=\"2.0\"\n" +
                "               xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                "        <Issuer>https://sts.windows.net/cf31badf-b9e1-40bd-aac9-1ac8beda0283/</Issuer>\n" +
                "        <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "            <SignedInfo>\n" +
                "                <CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "                <SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n" +
                "                <Reference URI=\"#_e0a4340f-29ac-49b9-8da0-9b22cb02d300\">\n" +
                "                    <Transforms>\n" +
                "                        <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
                "                        <Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "                    </Transforms>\n" +
                "                    <DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
                "                    <DigestValue>IYClYRYv2pJFNaZ2f6SCj51Ls2WtP+w82N98WaICnnI=</DigestValue>\n" +
                "                </Reference>\n" +
                "            </SignedInfo>\n" +
                "            <SignatureValue>\n" +
                "                KKjHa9Re8rLut4ke9Bf4StOh64jfT45a/WiHvscswoWAaJ9ZJfpmFUF+S0SgLYYlmbCrfQEYp86PLiN4yB71x6dXoEEueuFBPXiBdNQkQ4Eb5sMrbZ/1JzxD3vDMcRuuMHQ88YazutWvrLbTPk09vUYI9ZnircmSiU1JfvGN9I1Hq0JJAb4cP54Zi0Qd4sV+N1wfbF/3hCiCsjQrI2D0EJgVLn6QKSBfncK3ejd7tXGJyVWsdrtVDVq3Hey+RsaQjQ9oHX9IhpUitxq4PLA8AQHacwUXe4IPHhbTGp7X+nsIkqee+OzFvKV/iRYLRjP+8AzYOFI7Cwj6YDakCkOugQ==\n" +
                "            </SignatureValue>\n" +
                "            <KeyInfo>\n" +
                "                <X509Data>\n" +
                "                    <X509Certificate>\n" +
                "                        MIIDBTCCAe2gAwIBAgIQPCxFbySVSLZOggeWRzBWOjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIwMDYwNzAwMDAwMFoXDTI1MDYwNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOpZXSpuUXP7zCmtUTP07VL97ZrY+dsC0ayartd8hjN/4dHcK7tmT+d8uucA38+v7Swo6GLkQrlbI6Ft+/tM11DkSb2dC/dAgF/ufJVuzXBOGwMwNaV7+6EfZEMNF/HadGrVOB5x3mk1PC2cXIyTu/fx/XMYMGvnJSnxsZZXKLPE7LrqzPMYtnceVasM6jTAdrOtpdzEzewM3LR1IkAol9oiQKxowIbPpsUtcJsjCMjkoqXaHYY0FkQHLHlvmhVckUxVYvKJJdnE9RyYz13cdG9VqmEjs3kXa6y1HANKEdk86e8czmCWUhjZzS0KmvX+oeoedl219IgIMSoBA5UaWycCAwEAAaMhMB8wHQYDVR0OBBYEFFXP0ODFhjf3RS6oRijM5Tb+yB8CMA0GCSqGSIb3DQEBCwUAA4IBAQB9GtVikLTbJWIu5x9YCUTTKzNhi44XXogP/v8VylRSUHI5YTMdnWwvDIt/Y1sjNonmSy9PrioEjcIiI1U8nicveafMwIq5VLn+gEY2lg6KDJAzgAvA88CXqwfHHvtmYBovN7goolp8TY/kddMTf6TpNzN3lCTM2MK4Ye5xLLVGdp4bqWCOJ/qjwDxpTRSydYIkLUDwqNjv+sYfOElJpYAB4rTL/aw3ChJ1iaA4MtXEt6OjbUtbOa21lShfLzvNRbYK3+ukbrhmRl9lemJEeUls51vPuIe+jg+Ssp43aw7PQjxt4/MpfNMS2BfZ5F8GVSVG7qNb352cLLeJg5rc398Z\n" +
                "                    </X509Certificate>\n" +
                "                </X509Data>\n" +
                "            </KeyInfo>\n" +
                "        </Signature>\n" +
                "        <Subject>\n" +
                "            <NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">\n" +
                "                rKUTFD_GfWAxPmpv1AtjSOXLlzdetOZ4D5YdKdMCHzk\n" +
                "            </NameID>\n" +
                "            <SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                "                <SubjectConfirmationData InResponseTo=\"_db478146-73a9-4618-9f78-512463995100\"\n" +
                "                                         NotOnOrAfter=\"2020-08-27T07:23:53.386Z\"\n" +
                "                                         Recipient=\"https://sso-dev.pageroonline.com/authn/authentication/creative_ad_saml_authenticator\"/>\n" +
                "            </SubjectConfirmation>\n" +
                "        </Subject>\n" +
                "        <Conditions NotBefore=\"2020-07-27T06:18:53.386Z\" NotOnOrAfter=\"2020-08-27T07:23:53.386Z\">\n" +
                "            <AudienceRestriction>\n" +
                "                <Audience>spn:e169c08a-9224-4cb8-a7d0-d621136bbbd1</Audience>\n" +
                "            </AudienceRestriction>\n" +
                "        </Conditions>\n" +
                "        <AttributeStatement>\n" +
                "            <Attribute Name=\"http://schemas.microsoft.com/identity/claims/tenantid\">\n" +
                "                <AttributeValue>cf31badf-b9e1-40bd-aac9-1ac8beda0283</AttributeValue>\n" +
                "            </Attribute>\n" +
                "            <Attribute Name=\"http://schemas.microsoft.com/identity/claims/objectidentifier\">\n" +
                "                <AttributeValue>5d91acb4-4817-405d-8e53-b93625dbcad4</AttributeValue>\n" +
                "            </Attribute>\n" +
                "            <Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\">\n" +
                "                <AttributeValue>Chanaka.A@CreativeSoftware.com</AttributeValue>\n" +
                "            </Attribute>\n" +
                "            <Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname\">\n" +
                "                <AttributeValue>Anuruddha</AttributeValue>\n" +
                "            </Attribute>\n" +
                "            <Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname\">\n" +
                "                <AttributeValue>Chanaka</AttributeValue>\n" +
                "            </Attribute>\n" +
                "            <Attribute Name=\"http://schemas.microsoft.com/identity/claims/displayname\">\n" +
                "                <AttributeValue>Chanaka Anuruddha</AttributeValue>\n" +
                "            </Attribute>\n" +
                "            <Attribute Name=\"http://schemas.microsoft.com/identity/claims/identityprovider\">\n" +
                "                <AttributeValue>https://sts.windows.net/cf31badf-b9e1-40bd-aac9-1ac8beda0283/</AttributeValue>\n" +
                "            </Attribute>\n" +
                "            <Attribute Name=\"http://schemas.microsoft.com/claims/authnmethodsreferences\">\n" +
                "                <AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password\n" +
                "                </AttributeValue>\n" +
                "            </Attribute>\n" +
                "        </AttributeStatement>\n" +
                "        <AuthnStatement AuthnInstant=\"2020-07-27T06:23:38.619Z\" SessionIndex=\"_e0a4341f-29ac-49b9-8da0-9b22cb02d300\">\n" +
                "            <AuthnContext>\n" +
                "                <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>\n" +
                "            </AuthnContext>\n" +
                "        </AuthnStatement>\n" +
                "    </Assertion>\n" +
                "</samlp:Response>";
        String data = SamlToolkit.encodeSAML_post(postSAML);
        System.out.println(data);
//        Assert.assertEquals(data, postSAML_Payload);
    }

    @Test
    public void test_encode_signed_SAML_post() throws Exception {
        String data = SamlToolkit.encodeSAML_post(postSAML);
        Assert.assertEquals(data, postSAML_Payload);
    }
}
