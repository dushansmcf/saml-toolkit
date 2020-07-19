package test.saml2;

import org.bouncycastle.mime.encoding.Base64OutputStream;

import javax.crypto.CipherInputStream;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Base64;
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
}
