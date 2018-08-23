package com.sagar;

import sun.misc.BASE64Encoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.*;

public class AlexaURLInfoUtil {

    private static final String ACTION_NAME = "UrlInfo";
    // can add other group names as per requirement
    // api doc --> https://docs.aws.amazon.com/AlexaWebInfoService/latest/
    private static final String RESPONSE_GROUP_NAME = "RelatedLinks,Categories,Rank,UsageStats,LinksInCount";
    private static final String HASH_ALGORITHM = "HmacSHA256";
    private static final String DATEFORMAT_AWS = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    private static final String accessKeyId = "YOUR_ACCESS_KEY";
    private static final String secretAccessKey = "YOUR_SECRET_ACCESS_KEY";
    private static final String serviceHost = "awis.amazonaws.com";

    /**
     * Makes a request to the Alexa Web Information Service AlexaURLInfoUtil action
     */
    public String getAlexaInfo(final String site) throws Exception {
        // build query based on params.
        final String query = buildQuery(site);

        // message to sign
        final String toSign = "GET\n" + serviceHost + "\n/\n" + query;

        // generate signature
        final String signature = generateSignature(toSign);

        // request uri
        final String uri = "http://" + serviceHost + "/?" + query + "&Signature=" + URLEncoder.encode(signature, "UTF-8");

        System.out.println("Making request to:\n");
        System.out.println(uri + "\n");

        // Make the request and return response.
        return makeRequest(uri);
    }

    /**
     * Generates a timestamp for use with AWS request signing
     *
     * @param date current date
     * @return timestamp
     */
    private String getTimestampFromLocalTime(final Date date) {
        final SimpleDateFormat format = new SimpleDateFormat(DATEFORMAT_AWS);
        format.setTimeZone(TimeZone.getTimeZone("GMT"));
        return format.format(date);
    }

    /**
     * Computes RFC 2104-compliant HMAC signature.
     *
     * @param data The data to be signed.
     * @return The base64-encoded RFC 2104-compliant HMAC signature.
     * @throws java.security.SignatureException when signature generation fails.
     */
    private String generateSignature(final String data) throws java.security.SignatureException {
        final String signature;
        try {
            // get a hash key from the raw key bytes
            final SecretKeySpec signingKey = new SecretKeySpec(secretAccessKey.getBytes(), HASH_ALGORITHM);

            // get a hasher instance and initialize with the signing key
            final Mac mac = Mac.getInstance(HASH_ALGORITHM);
            mac.init(signingKey);

            // compute the hmac on input data bytes
            final byte[] rawHmac = mac.doFinal(data.getBytes());

            // base64-encode the hmac
            // result = Encoding.EncodeBase64(rawHmac);
            signature = new BASE64Encoder().encode(rawHmac);

        } catch (Exception e) {
            throw new SignatureException("Failed to generate HMAC : "
                    + e.getMessage());
        }
        return signature;
    }

    /**
     * Makes a request to the specified Url and return the results as a String
     *
     * @param requestUrl url to make request to
     * @return the XML document as a String
     * @throws IOException
     */
    private String makeRequest(final String requestUrl) throws IOException {
        final URL url = new URL(requestUrl);
        final URLConnection conn = url.openConnection();
        final InputStream in = conn.getInputStream();

        // Read the response
        final StringBuilder sb = new StringBuilder();
        int c;
        int lastChar = 0;
        while ((c = in.read()) != -1) {
            if (c == '<' && (lastChar == '>'))
                sb.append('\n');
            sb.append((char) c);
            lastChar = c;
        }
        in.close();
        return sb.toString();
    }


    /**
     * Builds the query string
     */
    private String buildQuery(final String site) throws UnsupportedEncodingException {
        final String timestamp = getTimestampFromLocalTime(Calendar.getInstance().getTime());
        final String[] sites = site.split(",");

        final Map<String, String> queryParams = new TreeMap<>();
        queryParams.put("Action", ACTION_NAME);
        queryParams.put("UrlInfo.Shared.ResponseGroup", RESPONSE_GROUP_NAME);
        queryParams.put("AWSAccessKeyId", accessKeyId);
        queryParams.put("Timestamp", timestamp);
//        queryParams.put("Url", site);
        queryParams.put("SignatureVersion", "2");
        queryParams.put("SignatureMethod", HASH_ALGORITHM);

        for (int i = 0; i < sites.length; i++) {
            queryParams.put("UrlInfo." + String.format("%d", i+1) + ".Url", sites[i]);
        }

        String query = "";
        boolean first = true;
        for (String name : queryParams.keySet()) {
            if (first)
                first = false;
            else
                query += "&";

            query += name + "=" + URLEncoder.encode(queryParams.get(name), "UTF-8");
        }

        return query;
    }

    public static void main(String...args)
            throws Exception
    {
        String site = "guardian.co.uk";
        AlexaURLInfoUtil urlInfoUtil = new AlexaURLInfoUtil();
        System.out.println(urlInfoUtil.getAlexaInfo(site));
    }
}
