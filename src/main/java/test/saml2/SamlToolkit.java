package test.saml2;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Base64;

public class SamlToolkit {
    public static String decodeSAML_redirect(String payload) throws Exception {
        byte[] data = Base64.getDecoder().decode(URLDecoder.decode(payload, "utf-8"));
        return Util.inflate(data, true);
    }

    public static String decodeSAML_POST(String payload) throws Exception {
        return new String(Base64.getDecoder().decode(payload), "utf-8");
    }
}
