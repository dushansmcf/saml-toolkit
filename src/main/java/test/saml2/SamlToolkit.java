package test.saml2;

import org.apache.commons.lang.RandomStringUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.*;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.saml2.core.Assertion;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;
import java.util.stream.DoubleStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class SamlToolkit {
    public static String decodeSAML_redirect(String payload) throws Exception {
        byte[] data = Base64.getDecoder().decode(URLDecoder.decode(payload, "utf-8"));
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
        return basicCredential;
    }

    public static void createSamlResponse() throws Exception {
        org.opensaml.DefaultBootstrap.bootstrap();
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = responseBuilder.buildObject();

        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
        Status status = new StatusBuilder().buildObject();
        status.setStatusCode(statusCode);
        response.setStatus(status);

        SAMLObjectBuilder<Assertion> assertionsBuilder = (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        Assertion ass = assertionsBuilder.buildObject();
        ass.setID(UUID.randomUUID().toString());
        ass.setIssueInstant(new DateTime());

        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue("https://sts.windows.net/cf31badf-b9e1-40bd-aac9-1ac8beda0283/");
        ass.setIssuer(issuer);

        Subject subject = new SubjectBuilder().buildObject(Subject.DEFAULT_ELEMENT_NAME);
        NameID nameId = new NameIDBuilder().buildObject();
        SubjectConfirmation subConfirm = new SubjectConfirmationBuilder().buildObject();
        nameId.setValue(RandomStringUtils.randomAlphabetic(44));
        subject.setNameID(nameId);

        ass.setSubject(subject);

        Element subjectElement = sign(response, ass);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(subjectElement);
        StreamResult result = new StreamResult(new FileWriter("test.saml.xml"));
        transformer.transform(source, result);
    }

    private static Element sign(Response response, Assertion ass) throws Exception {
        Credential cred = getCredential();
        org.opensaml.xml.signature.Signature signature = (org.opensaml.xml.signature.Signature) Configuration.getBuilderFactory().getBuilder(
                org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME).buildObject(
                org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(cred);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        SecurityConfiguration secConfiguration = Configuration.getGlobalSecurityConfiguration();

        NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfiguration.getKeyInfoGeneratorManager();
        KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
        KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(cred);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
        KeyInfo keyInfo = null;
        keyInfo = keyInfoGenerator.generate(cred);
        signature.setKeyInfo(keyInfo);
        SecurityHelper.prepareSignatureParams(signature, cred, null, "");

        ass.setSignature(signature);
        response.getAssertions().add(ass);
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Element subjectElement = marshallerFactory.getMarshaller(response).marshall(response);
        Signer.signObject(signature);
        return subjectElement;
    }

    public static void verifySignature() throws Exception {
        DefaultBootstrap.bootstrap();
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);
        FileInputStream fis = new FileInputStream("test.saml.xml");
        Document inCommonMDDoc = ppMgr.parse(fis);
        Element metadataRoot = inCommonMDDoc.getDocumentElement();
        // Get apropriate unmarshaller
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
        Response response = (Response) unmarshaller.unmarshall(metadataRoot);
        //Get Public Key
        BasicX509Credential publicCredential = new BasicX509Credential();
        PublicKey pubKey = KeyUtil.readPublicKeyFromFile("src/main/resources/pubkey.pem", "rsa");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKey.getEncoded(), "rsa");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(publicKeySpec);

        //Validate Public Key against Signature
        if (key != null) {
            publicCredential.setPublicKey(key);
            SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
            signatureValidator.validate(response.getAssertions().get(0).getSignature());
        }
    }


    public static void pirntResponse(Response response) throws Exception {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Element responseElement = marshallerFactory.getMarshaller(response).marshall(response);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(responseElement);
        StreamResult result = new StreamResult(new StringWriter());
        transformer.transform(source, result);
        System.out.println(result.getWriter().toString());
    }

    public static void main(String[] args) throws Exception {
        createSamlResponse();
        verifySignature();
    }
}
