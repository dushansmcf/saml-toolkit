package test.saml2;

import org.apache.commons.httpclient.auth.AuthState;
import org.apache.commons.lang.RandomStringUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.xacml.ctx.impl.AttributeValueTypeImplBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.saml2.core.Assertion;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;
import java.util.stream.DoubleStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class SamlToolkit {
    public static String decodeSAML_redirect(String payload, boolean doUrlEncode) throws Exception {
        String urlDecodePaylod = payload;
        if (doUrlEncode) {
            urlDecodePaylod = URLDecoder.decode(payload, "utf-8");
        }

        byte[] data = Base64.getDecoder().decode(urlDecodePaylod);
        return Util.inflate(data, true);
    }

    public static String decodeSAML_POST(String payload) throws Exception {
        byte[] data = Base64.getDecoder().decode(URLDecoder.decode(payload, "utf-8"));
        return new String(data, "utf-8");
    }

    public static String encodeSAML_redirect(String xml) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        DeflaterOutputStream dos = new DeflaterOutputStream(bos, deflater);
        dos.write(xml.getBytes());
        dos.finish();
        byte[] b64 = Base64.getEncoder().encode(bos.toByteArray());
        return URLEncoder.encode(new String(b64), "utf-8");
    }

    public static String encodeSAML_post(String xml) throws IOException {
        return URLEncoder.encode(Base64.getEncoder().encodeToString(xml.getBytes()), "utf-8");
    }

    private static Credential getCredential() throws Exception {
        PrivateKey pk = KeyUtil.readPrivateKeyFromFile("src/main/resources/key.pem", "rsa");
        BasicX509Credential basicCredential = new BasicX509Credential();
        basicCredential.setPrivateKey(pk);
        basicCredential.setEntityCertificate(KeyUtil.readX509CertificateFromFile("/home/sajith/scratch/saml-toolkit/src/main/resources/dev.localhost.crt"));
        return basicCredential;

    }

    public static Response createSamlResponse(String tenantId, String metadataUri) throws Exception {
        org.opensaml.DefaultBootstrap.bootstrap();
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        // change the namespace "<saml2p:Response>" to "<samlp:Response>"
        QName DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:protocol", "Response", "samlp");
        QName ISSUER_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "");

        ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(DEFAULT_ELEMENT_NAME);
        //SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        String inResponseTo = "_" + UUID.randomUUID().toString();
        String destination = "https://sso-dev.pageroonline.com/authn/authentication/creative_ad_saml_authenticator";
        Response response = responseBuilder.buildObject(DEFAULT_ELEMENT_NAME);
        response.setID(UUID.randomUUID().toString());
        response.setInResponseTo(inResponseTo);
        response.setDestination(destination);
        response.setIssueInstant(new DateTime());
        response.setID("_" + UUID.randomUUID().toString());

        Issuer issuer = new IssuerBuilder().buildObject(ISSUER_DEFAULT_ELEMENT_NAME);
        issuer.setValue(metadataUri);
        response.setIssuer(issuer);

        QName ASSERSION_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion", "");

        String assertionRef = UUID.randomUUID().toString();
        SAMLObjectBuilder<Assertion> assertionsBuilder = (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(ASSERSION_DEFAULT_ELEMENT_NAME);
        Assertion ass = assertionsBuilder.buildObject(ASSERSION_DEFAULT_ELEMENT_NAME);
        ass.setID("_" + assertionRef);
        ass.setIssueInstant(new DateTime());


        Issuer ass_issuer = new IssuerBuilder().buildObject(ISSUER_DEFAULT_ELEMENT_NAME);
        ass_issuer.setValue(metadataUri);
        ass.setIssuer(ass_issuer);

        QName STATUS_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:protocol", "Status", "samlp");
        QName STATUSCODE_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:protocol", "StatusCode", "samlp");


        StatusCode statusCode = new StatusCodeBuilder().buildObject(STATUSCODE_DEFAULT_ELEMENT_NAME);
        statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
        Status status = new StatusBuilder().buildObject(STATUS_DEFAULT_ELEMENT_NAME);
        status.setStatusCode(statusCode);
        response.setStatus(status);

        QName SUBJECT_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Subject", "");
        QName NAMEID_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "NameID", "");
        QName CONFIRMATIONDATA_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmationData", "");
        QName CONFIRMATION_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmation", "");

        Subject subject = new SubjectBuilder().buildObject(SUBJECT_DEFAULT_ELEMENT_NAME);
        NameID nameId = new NameIDBuilder().buildObject(NAMEID_DEFAULT_ELEMENT_NAME);
        SubjectConfirmationData subConfirmData = new SubjectConfirmationDataBuilder().buildObject(CONFIRMATIONDATA_DEFAULT_ELEMENT_NAME);
        subConfirmData.setInResponseTo(inResponseTo);
        subConfirmData.setNotOnOrAfter(new DateTime().plusHours(1));
        subConfirmData.setRecipient("https://sso-dev.pageroonline.com/authn/authentication/creative_ad_saml_authenticator");

        SubjectConfirmation subConfirm = new SubjectConfirmationBuilder().buildObject(CONFIRMATION_DEFAULT_ELEMENT_NAME);
        subConfirm.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        subConfirm.setSubjectConfirmationData(subConfirmData);

        nameId.setValue(RandomStringUtils.randomAlphabetic(44));
        subject.setNameID(nameId);
        subject.getSubjectConfirmations().add(subConfirm);

        ass.setSubject(subject);

        QName CONDITIONS_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Conditions", "");
        Conditions condition = new ConditionsBuilder().buildObject(CONDITIONS_DEFAULT_ELEMENT_NAME);
        DateTime now = new DateTime();
        condition.setNotBefore(now.minusHours(1));
        condition.setNotOnOrAfter(now.plusHours(1));
        AudienceRestriction audRestriction = new AudienceRestrictionBuilder().buildObject();
        Audience audience = new AudienceBuilder().buildObject();
        audience.setAudienceURI("XXX");
        audRestriction.getAudiences().add(audience);
        condition.getAudienceRestrictions().add(audRestriction);
        ass.setConditions(condition);

        QName ATTRBUTE_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeStatement", "");

        AttributeStatement as = new AttributeStatementBuilder().buildObject(ATTRBUTE_DEFAULT_ELEMENT_NAME);

        as.getAttributes().add(
                createAttribute("http://schemas.microsoft.com/identity/claims/tenantid", tenantId));
        as.getAttributes().add(
                createAttribute("http://schemas.microsoft.com/identity/claims/objectidentifier", UUID.randomUUID().toString())
        );
        as.getAttributes().add(
                createAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "chanaka.a@CreativeSoftware.com")
        );
        as.getAttributes().add(
                createAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "Anuruddha")
        );
        as.getAttributes().add(
                createAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "Chanaka")
        );
        as.getAttributes().add(
                createAttribute("http://schemas.microsoft.com/identity/claims/displayname", "Chanaka Anuruddha")
        );
        as.getAttributes().add(
                createAttribute("http://schemas.microsoft.com/identity/claims/identityprovider", metadataUri)
        );
        as.getAttributes().add(
                createAttribute("http://schemas.microsoft.com/claims/authnmethodsreferences", "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password")
        );

        ass.getAttributeStatements().add(as);

        QName CLASSREF_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnContextClassRef", "");
        QName CTX_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnContext", "");

        AuthnContextClassRef classRef = new AuthnContextClassRefBuilder().buildObject(CLASSREF_DEFAULT_ELEMENT_NAME);
        classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
        AuthnContext ctx = new AuthnContextBuilder().buildObject(CTX_DEFAULT_ELEMENT_NAME);
        ctx.setAuthnContextClassRef(classRef);

        QName authnStatement_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnStatement", "");
        AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject(authnStatement_DEFAULT_ELEMENT_NAME);
        authnStatement.setAuthnInstant(now);
        authnStatement.setSessionIndex("_" + assertionRef);
        authnStatement.setAuthnContext(ctx);

        ass.getAuthnStatements().add(authnStatement);
        sign(response, ass);
        return response;
    }

    private static Attribute createAttribute(String name, String value) {
        QName ATTRIBUTE_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute", "");
        QName ATTRIBUTEVALUE_DEFAULT_ELEMENT_NAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue", "");

        XSString att1val1 = (XSString) Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME).buildObject(
                ATTRIBUTEVALUE_DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        att1val1.setValue(value);
        Attribute attribute1 = new AttributeBuilder().buildObject(ATTRIBUTE_DEFAULT_ELEMENT_NAME);
        attribute1.setName(name);
        attribute1.getAttributeValues().add(att1val1);
        return attribute1;
    }

    private static void sign(Response response, Assertion ass) throws Exception {
        QName SIGNATURE_DEFAULT_ELEMENT_NAME = new QName("http://www.w3.org/2000/09/xmldsig#", "Signature", "");
        Credential cred = getCredential();
        org.opensaml.xml.signature.Signature signature = (org.opensaml.xml.signature.Signature) Configuration.getBuilderFactory().getBuilder(
                SIGNATURE_DEFAULT_ELEMENT_NAME).buildObject(
                org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);

        X509KeyInfoGeneratorFactory x509Factory = new X509KeyInfoGeneratorFactory();
        x509Factory.setEmitEntityCertificate(true);
        x509Factory.setEmitEntityCertificateChain(true);
        Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager().registerFactory("x509emitingKeyInfoGenerator", x509Factory);

        signature.setSigningCredential(cred);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        KeyInfoGenerator keyInfoGenerator = x509Factory.newInstance();

        KeyInfo keyInfo = null;
        keyInfo = keyInfoGenerator.generate(cred);
        signature.setKeyInfo(keyInfo);
        SecurityHelper.prepareSignatureParams(signature, cred, null, "");

        ass.setSignature(signature);
        response.getAssertions().add(ass);
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Element subjectElement = marshallerFactory.getMarshaller(response).marshall(response);
        Signer.signObject(signature);
    }

    public static void verifySignature(String filename) throws Exception {
        DefaultBootstrap.bootstrap();
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);
        FileInputStream fis = new FileInputStream(filename);
        Document inCommonMDDoc = ppMgr.parse(fis);
        Element metadataRoot = inCommonMDDoc.getDocumentElement();
        //Get apropriate unmarshaller
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
        Response response = (Response) unmarshaller.unmarshall(metadataRoot);
        //Get Public Key
        BasicX509Credential publicCredential = new BasicX509Credential();
        PublicKey pubKey = KeyUtil.readPublicKeyFromFile("src/main/resources/pubkey.pem", "rsa");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(publicKeySpec);

        //Validate Public Key against Signature
        if (key != null) {
            publicCredential.setPublicKey(key);
            SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
            signatureValidator.validate(response.getAssertions().get(0).getSignature());
        }
    }

    public static String toString(Response response) throws Exception {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Element responseElement = marshallerFactory.getMarshaller(response).marshall(response);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(responseElement);
        StreamResult result = new StreamResult(new StringWriter());
        transformer.transform(source, result);
        return result.getWriter().toString();
    }

    public static void toFile(Response response) throws Exception {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Element responseElement = marshallerFactory.getMarshaller(response).marshall(response);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(responseElement);
        StreamResult result = new StreamResult(new FileWriter("test.saml.xml"));
        transformer.transform(source, result);
    }

    public static void main(String[] args) throws Exception {
        Response r = createSamlResponse("cf31badf-b9e1-40bd-aac9-1ac8beda0283", "https://sts.windows.net/cf31badf-b9e1-40bd-aac9-1ac8beda0283/");
        toFile(r);
        verifySignature("test.saml.xml");
    }

    private static XMLObject buildXMLObject(QName objectQName) {

        XMLObjectBuilder builder =
                org.opensaml.xml.Configuration.getBuilderFactory()
                        .getBuilder(objectQName);
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(),
                objectQName.getPrefix());
    }
}
