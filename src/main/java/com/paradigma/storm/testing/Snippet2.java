package com.paradigma.storm.testing;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.DefaultHttpClientConnection;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.*;
import org.apache.http.util.EntityUtils;
import twitter4j.internal.org.json.JSONException;
import twitter4j.internal.org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.*;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.UUID;

/**
 * Created with IntelliJ IDEA.
 * User: dcarroza
 * Date: 16/01/14
 * Time: 12:44
 * To change this template use File | Settings | File Templates.
 */
public class Snippet2 {

    public static String read(String url) {
        StringBuffer buffer = new StringBuffer();
        try {
            /**
             * get the time - note: value below zero
             * the millisecond value is used for oauth_nonce later on
             */
            int millis = (int) System.currentTimeMillis() * -1;
            int time = (int) millis / 1000;

            /**
             * Listing of all parameters necessary to retrieve a token
             * (sorted lexicographically as demanded)
             */
            String[][] data = {
                    {"oauth_consumer_key", "Rcif1a6M0Amqvx5xIBRegg"},
                    {"oauth_nonce",  "bc2193577d70244dfdbec88ded4c067b"}, //String.valueOf(millis)},
                    {"oauth_signature", "eVzs%2BSax0WVBMulaYIxF0vHQtnY%3D"},
                    {"oauth_signature_method", "HMAC-SHA1"},
                    {"oauth_timestamp", "1389889535"}, //String.valueOf(time)},
                    {"oauth_version", "1.0"}
            };

            /**
             * Generation of the signature base string
             */
            String signature_base_string =
                    "POST&"+ URLEncoder.encode(url, "UTF-8")+"&";
            for(int i = 0; i < data.length; i++) {
                // ignore the empty oauth_signature field
                if(i != 3) {
                    signature_base_string +=
                            URLEncoder.encode(data[i][0], "UTF-8") + "%3D" +
                                    URLEncoder.encode(data[i][1], "UTF-8") + "%26";
                }
            }
            // cut the last appended %26
            signature_base_string = signature_base_string.substring(0,
                    signature_base_string.length()-3);

            /**
             * Sign the request
             */
            Mac m = Mac.getInstance("HmacSHA1");
            m.init(new SecretKeySpec("CONSUMER_SECRET".getBytes(), "HmacSHA1"));
            m.update(signature_base_string.getBytes());
            byte[] res = m.doFinal();
            String sig = String.valueOf(new Base64().encode(res));
            data[3][1] = sig;

            /**
             * Create the header for the request
             */
            String header = "OAuth ";
            for(String[] item : data) {
                header += item[0]+"=\""+item[1]+"\", ";
            }
            // cut off last appended comma
            header = header.substring(0, header.length()-2);

            System.out.println("Signature Base String: "+signature_base_string);
            System.out.println("Authorization Header: "+header);
            System.out.println("Signature: "+sig);

            String charset = "UTF-8";
            URLConnection connection = new URL(url).openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestProperty("Accept-Charset", charset);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=" + charset);
            connection.setRequestProperty("Authorization", header);
            connection.setRequestProperty("User-Agent", "XXXX");
            OutputStream output = connection.getOutputStream();
            output.write(header.getBytes(charset));

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));

            String read;
            while((read = reader.readLine()) != null) {
                buffer.append(read);
            }
        }
        catch(Exception e) {
            e.printStackTrace();
        }

        return buffer.toString();
    }

    private static final String PROTECTED_RESOURCE_URL = "https://stream.twitter.com/1.1/statuses/sample.json";

    private static String twitter_consumer_key = "Rcif1a6M0Amqvx5xIBRegg";
    private static String twitter_consumer_secret = "eIlCsI0smBj3mKzKG23Ddezn4dxBCUZHwcZ88fmpZs";

    public static void main(String[] args) throws Exception{
//        System.out.println(Snippet2.read("https://stream.twitter.com/1.1/statuses/firehose.json"));

//        OAuthService service = new ServiceBuilder()
//                .provider(TwitterApi.class)
//                .apiKey("Rcif1a6M0Amqvx5xIBRegg")
//                .apiSecret("eIlCsI0smBj3mKzKG23Ddezn4dxBCUZHwcZ88fmpZs")
//                .build();
//
//        Token requestToken = service.getRequestToken();
//        String your_token = requestToken.getToken();
//
//        Verifier verifier = new Verifier(your_token);
//        Token accessToken = service.getAccessToken(requestToken, verifier);
//
//        OAuthRequest request = new OAuthRequest(Verb.GET, "https://stream.twitter.com/1.1/statuses/firehose.json");
//        service.signRequest(accessToken, request);
//        Response response = request.send();
//
//        System.out.println(response);

        // If you choose to use a callback, "oauth_verifier" will be the return value by Twitter (request param)
//        OAuthService service = new ServiceBuilder()
//                .provider(TwitterApi.class)
//                .apiKey("Rcif1a6M0Amqvx5xIBRegg")
//                .apiSecret("eIlCsI0smBj3mKzKG23Ddezn4dxBCUZHwcZ88fmpZs")
//                .build();
//        Scanner in = new Scanner(System.in);
//
//        System.out.println("=== Twitter's OAuth Workflow ===");
//        System.out.println();
//
//        // Obtain the Request Token
//        System.out.println("Fetching the Request Token...");
//        Token requestToken = service.getRequestToken();
//        System.out.println("Got the Request Token!");
//        System.out.println();
//
//        System.out.println("Now go and authorize Scribe here:");
//        System.out.println(service.getAuthorizationUrl(requestToken));
//        System.out.println("And paste the verifier here");
//        System.out.print(">>");
//        Verifier verifier = new Verifier(in.nextLine());
//        System.out.println();
//
//        // Trade the Request Token and Verfier for the Access Token
//        System.out.println("Trading the Request Token for an Access Token...");
//        Token accessToken = service.getAccessToken(requestToken, verifier);
//        System.out.println("Got the Access Token!");
//        System.out.println("(if your curious it looks like this: " + accessToken + " )");
//        System.out.println();
//
//        // Now let's go and ask for a protected resource!
//        System.out.println("Now we're going to access a protected resource...");
//        OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
//        request.addBodyParameter("status", "this is sparta! *");
//        service.signRequest(accessToken, request);
//        Response response = request.send();
//        System.out.println("Got it! Lets see what we found...");
//        System.out.println();
//        System.out.println(response.getBody());
//
//        System.out.println();
//        System.out.println("Thats it man! Go and build something awesome with Scribe! :)");


        String oauth_signature_method = "HMAC-SHA1";
        String uuid_string = UUID.randomUUID().toString();
        uuid_string = uuid_string.replaceAll("-", "");
        String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here. I used UUID minus "-" signs
        String oauth_timestamp = (new Long(System.currentTimeMillis()/1000)).toString(); // get current time in milliseconds, then divide by 1000 to get seconds
        // I'm not using a callback value. Otherwise, you'd need to include it in the parameter string like the example above
        // the parameter string must be in alphabetical order
        String parameter_string = "oauth_consumer_key=" + twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + "&oauth_timestamp=" + oauth_timestamp + "&oauth_version=1.0";
        System.out.println("parameter_string=" + parameter_string);
        String signature_base_string = "POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&" + URLEncoder.encode(parameter_string, "UTF-8");
        System.out.println("signature_base_string=" + signature_base_string);
        String oauth_signature = "";
        try {
            oauth_signature = computeSignature(signature_base_string, "eIlCsI0smBj3mKzKG23Ddezn4dxBCUZHwcZ88fmpZs&");  // note the & at the end. Normally the user access_token would go here, but we don't know it yet for request_token
            System.out.println("oauth_signature=" + URLEncoder.encode(oauth_signature, "UTF-8"));
        } catch (GeneralSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" +
                oauth_timestamp + "\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + URLEncoder.encode(oauth_signature, "UTF-8") + "\"";
        System.out.println("authorization_header_string=" + authorization_header_string);

        String oauth_token = "";
        HttpClient httpclient = new DefaultHttpClient();
        try {
            HttpPost httppost = new HttpPost("https://api.twitter.com/oauth/request_token");
            httppost.setHeader("Authorization",authorization_header_string);
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            String responseBody = httpclient.execute(httppost, responseHandler);
            oauth_token = responseBody.substring(responseBody.indexOf("oauth_token=") + 12, responseBody.indexOf("&oauth_token_secret="));
            System.out.println("responseBody: " + responseBody);

            showTweeterInfo(oauth_token, "eIlCsI0smBj3mKzKG23Ddezn4dxBCUZHwcZ88fmpZs");

        } catch(ClientProtocolException cpe)  {  System.out.println(cpe.getMessage());  }
        catch(IOException ioe) {   System.out.println(ioe.getMessage());  }
        finally { httpclient.getConnectionManager().shutdown();  }
    }




    private static void showTweeterInfo(String oauth_token, String oauth_token_secret) {
        JSONObject jsonresponse = new JSONObject();

        // generate authorization header
        String get_or_post = "GET";
        String oauth_signature_method = "HMAC-SHA1";

        String uuid_string = UUID.randomUUID().toString();
        uuid_string = uuid_string.replaceAll("-", "");
        String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here

        // get the timestamp
        Calendar tempcal = Calendar.getInstance();
        long ts = tempcal.getTimeInMillis();// get current time in milliseconds
        String oauth_timestamp = (new Long(ts/1000)).toString(); // then divide by 1000 to get seconds

        // the parameter string must be in alphabetical order
        // this time, I add 3 extra params to the request, "lang", "result_type" and "q".
        String parameter_string = "oauth_consumer_key=" + twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method +
                "&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + encode(oauth_token) + "&oauth_version=1.0";
        //System.out.println("parameter_string=" + parameter_string);
        String twitter_endpoint = "https://stream.twitter.com/1.1/statuses/firehose.json";
        String twitter_endpoint_host = "stream.twitter.com";
        String twitter_endpoint_path = "/1.1/statuses/statuses/firehose.json";
        String signature_base_string = get_or_post + "&"+ encode(twitter_endpoint) + "&" + encode(parameter_string);
        //System.out.println("signature_base_string=" + signature_base_string);

        // this time the base string is signed using twitter_consumer_secret + "&" + encode(oauth_token_secret) instead of just twitter_consumer_secret + "&"
        String oauth_signature = "";
        try {
            oauth_signature = computeSignature(signature_base_string, twitter_consumer_secret + "&" + encode(oauth_token_secret));  // note the & at the end. Normally the user access_token would go here, but we don't know it yet for request_token
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp +
                "\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + encode(oauth_signature) + "\",oauth_token=\"" + encode(oauth_token) + "\"";
        //System.out.println("authorization_header_string=" + authorization_header_string);


        HttpParams params = new SyncBasicHttpParams();
        HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
        HttpProtocolParams.setContentCharset(params, "UTF-8");
        HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
        HttpProtocolParams.setUseExpectContinue(params, false);

        HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
                // Required protocol interceptors
                new RequestContent(),
                new RequestTargetHost(),
                // Recommended protocol interceptors
                new RequestConnControl(),
                new RequestUserAgent(),
                new RequestExpectContinue()});

        HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
        HttpContext context = new BasicHttpContext(null);
        HttpHost host = new HttpHost(twitter_endpoint_host,443);
        DefaultHttpClientConnection conn = new DefaultHttpClientConnection();

        context.setAttribute(ExecutionContext.HTTP_CONNECTION, conn);
        context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);

        try {
            try {
                SSLContext sslcontext = SSLContext.getInstance("TLS");
                sslcontext.init(null, null, null);
                SSLSocketFactory ssf = sslcontext.getSocketFactory();
                Socket socket = ssf.createSocket();
                socket.connect(
                        new InetSocketAddress(host.getHostName(), host.getPort()), 0);
                conn.bind(socket, params);

                // the following line adds 3 params to the request just as the parameter string did above. They must match up or the request will fail.
                BasicHttpEntityEnclosingRequest request2 = new BasicHttpEntityEnclosingRequest("GET", twitter_endpoint_path);
                request2.setParams(params);
                request2.addHeader("Authorization", authorization_header_string); // always add the Authorization header
                httpexecutor.preProcess(request2, httpproc, context);
                HttpResponse response2 = httpexecutor.execute(request2, conn, context);
                response2.setParams(params);
                httpexecutor.postProcess(response2, httpproc, context);

                if(response2.getStatusLine().toString().indexOf("500") != -1)
                {
                    jsonresponse.put("response_status", "error");
                    jsonresponse.put("message", "Twitter auth error.");
                }
                else
                {
                    // if successful, the response should be a JSONObject of tweets
                    JSONObject jo = new JSONObject(EntityUtils.toString(response2.getEntity()));
                    if(jo.has("errors"))
                    {
                        jsonresponse.put("response_status", "error");
                        String message_from_twitter = jo.getJSONArray("errors").getJSONObject(0).getString("message");
                        if(message_from_twitter.equals("Invalid or expired token") || message_from_twitter.equals("Could not authenticate you"))
                            jsonresponse.put("message", "Twitter auth error.");
                        else
                            jsonresponse.put("message", jo.getJSONArray("errors").getJSONObject(0).getString("message"));
                    }
                    else
                    {
                        jsonresponse = jo; // this is the full result object from Twitter
                    }

                    conn.close();
                }
            }
            catch(HttpException he)
            {
                System.out.println(he.getMessage());
                jsonresponse.put("response_status", "error");
                jsonresponse.put("message", "getTweet HttpException message=" + he.getMessage());
            }
            catch(NoSuchAlgorithmException nsae)
            {
                System.out.println(nsae.getMessage());
                jsonresponse.put("response_status", "error");
                jsonresponse.put("message", "getTweet NoSuchAlgorithmException message=" + nsae.getMessage());
            }
            catch(KeyManagementException kme)
            {
                System.out.println(kme.getMessage());
                jsonresponse.put("response_status", "error");
                jsonresponse.put("message", "getTweet KeyManagementException message=" + kme.getMessage());
            }
            finally {
                conn.close();
            }
        }
        catch(JSONException jsone)
        {

        }
        catch(IOException ioe)
        {

        }

        System.out.println(jsonresponse);
    }

    /*
         * Updated UrlEncode method to handle *, +, ~ correctly
         */
    private static String encode(String value) {
        String encoded = null;
        try {
            encoded = URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException ignore) {
        }
        StringBuilder buffer = new StringBuilder(encoded.length());
        char focus;
        for (int i = 0; i < encoded.length(); i++) {
            focus = encoded.charAt(i);
            if (focus == '*') {
                buffer.append("%2A");
            } else if (focus == '+') {
                buffer.append("%20");
            } else if (focus == '%' && (i + 1) < encoded.length() && encoded.charAt(i + 1) == '7' && encoded.charAt(i + 2) == 'E') {
                buffer.append('~');
                i += 2;
            } else {
                buffer.append(focus);
            }
        }
        return buffer.toString();
    }

    private static String computeSignature(String baseString, String keyString) throws GeneralSecurityException, UnsupportedEncodingException {

        SecretKey secretKey = null;

        byte[] keyBytes = keyString.getBytes();
        secretKey = new SecretKeySpec(keyBytes, "HmacSHA1");

        Mac mac = Mac.getInstance("HmacSHA1");

        mac.init(secretKey);

        byte[] text = baseString.getBytes();

        return new String(Base64.encodeBase64(mac.doFinal(text))).trim();
    }


}
