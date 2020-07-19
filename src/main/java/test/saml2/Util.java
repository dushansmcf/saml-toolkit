package test.saml2;

import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class Util {
    static String rawReq = "fZJRb9sgFIXf9yss3rGB2Aqg2FW2qlqlTosadw97iQBfp0g2ZICj%2Ffw5TqtmL31BIA7fufceNnd%2FxyE7Q4jWuxrRnKAMnPGddccavbQPmKO75ssmqnFgJ7md0qt7hj8TxJRtY4SQ5nffvIvTCGEP4WwNvDw%2F1eg1pVOURRGjxx2c85M6QvDeDdZBbvxYqAtqWcEla9QFVJgA8%2BYMB9UdLpaHm3sfUHY%2F%2B1q3aD8sBn%2B0Lh%2BtCT76Pt14mH5Ftep6rAVQXBLdYaWMwFQZrqFThPFVsbSGsgcfDCz91SiFCVD2eF%2BjA%2B00FwQ0rqp%2BRnSsx0KVCgteVSU3DDTXszTGCR5dTMqlGjHCCCZrTNct4bJisuS5oOI3ynbBJ2%2F88NW664Sn4KRX0Ubp1AhRJiP32x9PkuVE6qsoyu9tu8O7n%2FsWZb%2Fek2KXpObsXJTXbD5nnd6MUXONUi4Vh1vC5wD1HjZqaNmzqlsRbED3uCz7cp4GM5itqSGCMkLWYlPc2jRvx%2F8%2FUPMP";
    static String rawResp = "PHNhbWxwOlJlc3BvbnNlIElEPSJfODAwZTU2OTItMDZlNS00ZjBjLTg5MTMtNGY1NmU5MWVkYWY3IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyMC0wNy0xN1QwODo1MzoyOC40NjlaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9zc28tZGV2LnBhZ2Vyb29ubGluZS5jb20vYXV0aG4vYXV0aGVudGljYXRpb24vY3JlYXRpdmVfYWRfc2FtbF9hdXRoZW50aWNhdG9yIiBJblJlc3BvbnNlVG89Il8xZGI4OTBlYi01NWYxLTRkMmYtOWE0YS05ODU1NDhjMmViOGIiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2NmMzFiYWRmLWI5ZTEtNDBiZC1hYWM5LTFhYzhiZWRhMDI4My88L0lzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48QXNzZXJ0aW9uIElEPSJfNTRiZTA2MDgtYTg1MC00Y2E4LWFiYzUtMjM4YTVhNzQwMjAzIiBJc3N1ZUluc3RhbnQ9IjIwMjAtMDctMTdUMDg6NTM6MjguNDY5WiIgVmVyc2lvbj0iMi4wIiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI";

    public static void main(String[] args) throws Exception {
        Init.init();
        String ud = URLDecoder.decode(rawReq,"utf-8");
        byte[] decodedRequest = decodeBase64b(ud);
        String xml = inflate(decodedRequest,true);
        System.out.println(xml);

        byte []input = Base64.decode(rawResp);
        InflaterInputStream inflater = new InflaterInputStream(new ByteArrayInputStream(input), new Inflater(true));
        byte[]xxx = inflater.readAllBytes();
    }

    public static byte[] decodeBase64b(String b64Data) throws Base64DecodingException {
        return Base64.decode(b64Data);
    }

    public static String inflate(byte[] deflatedData, boolean supportGzipCompression) throws Exception {
        try {
            byte[] inflatedData = new byte[(10 * deflatedData.length)];
            Inflater decompresser = new Inflater(supportGzipCompression);
            decompresser.setInput(deflatedData, 0, deflatedData.length);
            int inflatedBytesLength = decompresser.inflate(inflatedData);
            decompresser.end();
            return new String(inflatedData, 0, inflatedBytesLength);
        } catch (DataFormatException dfe) {
            throw new Exception(dfe);
        }
    }
}
