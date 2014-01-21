package com.paradigma.tweeter;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.*;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultHttpClientConnection;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.*;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/*
 * This is a re-factoring and extension of the following code
 * 
 * https://github.com/cyrus7580/twitter_api_examples
 * 
 * Goals were to:
 * - take it apart and rebuild it to understand it. 
 * - refactor to avoid repeated code
 * - demonstrate approach working with JSF
 * - run on OpenShift with JBoss AS7
 * - allow different twitter applications for login and for publishing
 * 
 * Thanks for the great resource Cyrus, I hope you or others find this useful.
 * 
 * Andrew Simpson @ams10961
 *  
 */
public class TwitterServices {

	final static Logger logger = LoggerFactory.getLogger(TwitterServices.class);

	private static final String OAH_CALLBACK_CONFIRMED = "oauth_callback_confirmed";
	private static final String METHOD_POST = "POST";
	private static final String METHOD_GET = "GET";
	private static final int SSL_PORT = 443;
	private static final String EQUALS = "=";
	private static final String QUOTE = "\"";
	private static final String AMPERSAND = "&";
	private static final String QUESTION_MARK = "?";
	private static final String COMMA = ", ";
	private static final String SPACE = " ";
	
	private static final String OAH_AUTHORISATION = "Authorization";
	private static final String OAH_OAUTH = "OAuth";
	private static final String OAH_CONSUMER_KEY = "oauth_consumer_key";
	private static final String OAH_NONCE = "oauth_nonce";
	private static final String OAH_SIGNATURE = "oauth_signature";
	private static final String OAH_SIGNATURE_METHOD = "oauth_signature_method";
	private static final String OAH_SIGNATURE_METHOD_VALUE = "HMAC-SHA1";
	private static final String OAH_TIMESTAMP = "oauth_timestamp";
	private static final String OAH_VERSION = "oauth_version";
	private static final String OAH_VERSION_VALUE = "1.0";
	public static final String OAH_TOKEN = "oauth_token";
	public static final String OAH_VERIFIER = "oauth_verifier";
	public static final String OAH_TOKEN_SECRET = "oauth_token_secret";

	private static final String CRYPTO_SPEC = "HmacSHA1";
	private static final String TRANSPORT_LAYER_SECURITY = "TLS";
	private static final String HTTP_ENCODING = "UTF-8";
	private static final String HTTP_USER_AGENT = "HttpCore/1.1";

	// Twitter 
	private static final String TWITTER_ENDPOINT_HOST = "api.twitter.com";
	public static final String TWITTER_USER_ID = "user_id";
	public static final String TWITTER_SCREEN_NAME = "screen_name";

	private static final String TWITTER_AUTHENTICATION_ENDPOINT = "https://api.twitter.com/oauth/authorize";

	private static final String TWITTER_ACCESS_TOKEN_ENDPOINT = "https://api.twitter.com/oauth/access_token";
	private static final String TWITTER_ACCESS_TOKEN_ENDPOINT_PATH = "/oauth/access_token";
	
	/*
	 * 
	 */
	private static String generateNumberUsedOnce() {
		return UUID.randomUUID().toString().replaceAll("-", "");
	}

	/*
	 * 
	 */
	private static final String currentTimeInSeconds() {
		Calendar now = Calendar.getInstance();
		return new Long(now.getTimeInMillis() / 1000).toString();
	}

	/*
	 * Updated UrlEncode method to handle *, +, ~ correctly
	 */
	private static String encode(String value) {
		String encoded = null;
		try {
			encoded = URLEncoder.encode(value, HTTP_ENCODING);
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

	/*
	 * 
	 */
	private static String computeSignature(String baseString, String keyString) throws GeneralSecurityException,
			UnsupportedEncodingException {
		SecretKey secretKey = null;

		byte[] keyBytes = keyString.getBytes();
		secretKey = new SecretKeySpec(keyBytes, CRYPTO_SPEC);

		Mac mac = Mac.getInstance(CRYPTO_SPEC);
		mac.init(secretKey);

		byte[] text = baseString.getBytes();

		return new String(Base64.encodeBase64(mac.doFinal(text))).trim();
	}

	/*
	 * https://dev.twitter.com/docs/auth/creating-signature
	 */
	private static String generateOauthSignature(HashMap<String, String> signatureParameters,
			String endPoint, String consumerSecret, String tokenSecret, String httpMethod) 
					throws GeneralSecurityException, UnsupportedEncodingException {

		// Using a tree map will ensure that keys are in alphabetical order
		TreeMap<String, String> paramMap = new TreeMap<String, String>();

		// add static values
		paramMap.put(OAH_SIGNATURE_METHOD, OAH_SIGNATURE_METHOD_VALUE);
		paramMap.put(OAH_VERSION, OAH_VERSION_VALUE);

		// add dynamic values
		paramMap.putAll(signatureParameters);

		// construct parameter string, URL encode keys and values, TreeMap keeps
		// alphabetical order
		StringBuffer paramString = new StringBuffer();
		Set<String> keys = paramMap.keySet();
		for (Iterator<String> it = keys.iterator(); it.hasNext();) {
			String key = (String) it.next();
			String value = (String) paramMap.get(key);
			// added encoded key/value pairs
			paramString.append(encode(key));
			paramString.append(EQUALS);
			paramString.append(encode(value));
			if (it.hasNext()) {
				paramString.append(AMPERSAND);
			}
		}

		StringBuffer baseString = new StringBuffer();
		baseString.append(httpMethod);
		baseString.append(AMPERSAND);
		baseString.append(encode(endPoint));
		baseString.append(AMPERSAND);
		baseString.append(encode(paramString.toString()));

		StringBuffer signingKey = new StringBuffer();
		signingKey.append(consumerSecret);
		signingKey.append(AMPERSAND);
		// tokenSecret not always known at this point, e.g. during sign-in
		if (tokenSecret != null) {
			signingKey.append(tokenSecret);
		}

		// HmacSHA1 hash base string against consumer secret.
		String result = computeSignature(baseString.toString(), signingKey.toString());
		logger.info(result);
		return result;
	}

	/*
	 * 
	 */
	private static String generateOauthHeader(HashMap<String, String> headerParameters, String signature) {

		// TreeMap ensures alphabetical order
		TreeMap<String, String> paramMap = new TreeMap<String, String>();

		// add static values
		paramMap.put(OAH_SIGNATURE_METHOD, OAH_SIGNATURE_METHOD_VALUE);
		paramMap.put(OAH_VERSION, OAH_VERSION_VALUE);

		// add dynamic values
//		paramMap.put(OAH_SIGNATURE, signature);
		paramMap.putAll(headerParameters);

		// construct the parameter String, URL encode, TreeMap ensures
		// alphabetical order
		StringBuffer authHeader = new StringBuffer();
		authHeader.append(OAH_OAUTH).append(SPACE);
		Set<String> keys = paramMap.keySet();
		for (Iterator<String> it = keys.iterator(); it.hasNext();) {
			String key = (String) it.next();
			String value = (String) paramMap.get(key);
			// added encoded key/value pairs
			authHeader.append(encode(key));
			authHeader.append(EQUALS);
			authHeader.append(QUOTE);
			authHeader.append(encode(value));
			authHeader.append(QUOTE);
			if (it.hasNext()) {
				authHeader.append(COMMA);
			}
		}
		String result = authHeader.toString();
		logger.info(result);
		return result;
	}

	/*
	 * 
	 */
	private static final String assembleRequestBody(HashMap<String, String> bodyParameters) {

		// Using a tree map will ensure that keys are in alphabetical order
		TreeMap<String, String> paramMap = new TreeMap<String, String>();

		// add any additional parameters
		paramMap.putAll(bodyParameters);

		// construct the parameter String, TreeMap should make sure it's
		// alphabetical
		StringBuffer paramString = new StringBuffer();
		Set<String> keys = paramMap.keySet();
		for (Iterator<String> it = keys.iterator(); it.hasNext();) {
			String key = (String) it.next();
			String value = (String) paramMap.get(key);
			// added encoded key/value pairs
			paramString.append(encode(key));
			paramString.append(EQUALS);
			paramString.append(encode(value));
			if (it.hasNext()) {
				paramString.append(AMPERSAND);
			}
		}
		String result = paramString.toString();
		logger.info(result);
		return result;
	}

	/*
	 * 
	 */

	private static String makeHttpRequest(String endPointHost, String endPointPath, String authHeader, String requestBody, String httpMethod)
			throws TwitterException {

		HttpParams _httpParams = new SyncBasicHttpParams();
		HttpProtocolParams.setVersion(_httpParams, HttpVersion.HTTP_1_1);
		HttpProtocolParams.setContentCharset(_httpParams, HTTP_ENCODING);
		HttpProtocolParams.setUserAgent(_httpParams, HTTP_USER_AGENT);
		HttpProtocolParams.setUseExpectContinue(_httpParams, false);

		HttpProcessor _httpProcessor = new ImmutableHttpProcessor(new HttpRequestInterceptor[] { new RequestContent(),
				new RequestTargetHost(), new RequestConnControl(), new RequestUserAgent(), new RequestExpectContinue() });

		HttpRequestExecutor _httpExecutor = new HttpRequestExecutor();
		HttpContext _httpContext = new BasicHttpContext(null);
		HttpHost _httpHost = new HttpHost(endPointHost, SSL_PORT);
		DefaultHttpClientConnection _httpConnection = new DefaultHttpClientConnection();

		_httpContext.setAttribute(ExecutionContext.HTTP_CONNECTION, _httpConnection);
		_httpContext.setAttribute(ExecutionContext.HTTP_TARGET_HOST, _httpHost);

		try {
			// initialize the HTTPS connection
			SSLContext _sslcontext = SSLContext.getInstance(TRANSPORT_LAYER_SECURITY);
			_sslcontext.init(null, null, null);
			SSLSocketFactory _sslSocketFactory = _sslcontext.getSocketFactory();
			Socket _socket = _sslSocketFactory.createSocket();
			_socket.connect(new InetSocketAddress(_httpHost.getHostName(), _httpHost.getPort()), 0);
			_httpConnection.bind(_socket, _httpParams);

			BasicHttpEntityEnclosingRequest _httpRequest = new BasicHttpEntityEnclosingRequest(httpMethod, endPointPath);

			// add request body
			_httpRequest.setEntity(new StringEntity(requestBody, ContentType.APPLICATION_FORM_URLENCODED));

			// set the authorisation parameters
			_httpRequest.setParams(_httpParams);
			_httpRequest.addHeader(OAH_AUTHORISATION, authHeader);

			// preprocess request
			_httpExecutor.preProcess(_httpRequest, _httpProcessor, _httpContext);

			// log request
			logger.info(_httpRequest.toString());

			// execute request
			HttpResponse _httpResponse = _httpExecutor.execute(_httpRequest, _httpConnection, _httpContext);

			// check response
			if (_httpResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
				logger.error(_httpResponse.toString());
				throw new TwitterException("HTTP Request was not successful");
			}

			// post process response
			_httpResponse.setParams(_httpParams);
			_httpExecutor.postProcess(_httpResponse, _httpProcessor, _httpContext);

			// log response
			logger.info(_httpResponse.toString());

			// return response body
			return EntityUtils.toString(_httpResponse.getEntity());

		} catch (IOException ioe) {
			throw new TwitterException("IO Exception", ioe);
		} catch (HttpException he) {
			throw new TwitterException("HTTP Exception", he);
		} catch (NoSuchAlgorithmException nsae) {
			throw new TwitterException("SSL Algorithm Exception", nsae);
		} catch (KeyManagementException kme) {
			throw new TwitterException("Key Management Exception", kme);
		} finally {
			try {
				_httpConnection.close();
			} catch (IOException e) {
				logger.error("io exception", e);
			}
		}
	}

	/*
	 * Sign in with Twitter Step 1 - get request token
	 */

	public static HashMap<String, String> getRequestToken() throws TwitterException {

        String oauth_signature_method = "HMAC-SHA1";
        String uuid_string = UUID.randomUUID().toString();
        uuid_string = uuid_string.replaceAll("-", "");
        String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here. I used UUID minus "-" signs
        String oauth_timestamp = (new Long(System.currentTimeMillis()/1000)).toString(); // get current time in milliseconds, then divide by 1000 to get seconds
        // I'm not using a callback value. Otherwise, you'd need to include it in the parameter string like the example above
        // the parameter string must be in alphabetical order
        String parameter_string = "oauth_consumer_key=" + TwitterCredentials.TWITTER_SERVICES_CONSUMER_KEY + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + "&oauth_timestamp=" + oauth_timestamp + "&oauth_version=1.0";
        System.out.println("parameter_string=" + parameter_string);
        String signature_base_string = null;
        try {
            signature_base_string = "POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&" + URLEncoder.encode(parameter_string, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        System.out.println("signature_base_string=" + signature_base_string);
        String oauth_signature = "";
        try {
            oauth_signature = computeSignature(signature_base_string, "eIlCsI0smBj3mKzKG23Ddezn4dxBCUZHwcZ88fmpZs&");  // note the & at the end. Normally the user access_token would go here, but we don't know it yet for request_token
            System.out.println("oauth_signature=" + URLEncoder.encode(oauth_signature, "UTF-8"));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        String authorization_header_string = null;
        try {
            authorization_header_string = "OAuth oauth_consumer_key=\"" + TwitterCredentials.TWITTER_SERVICES_CONSUMER_KEY + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" +
                    oauth_timestamp + "\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + URLEncoder.encode(oauth_signature, "UTF-8") + "\"";
            System.out.println("authorization_header_string=" + authorization_header_string);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }

        String oauth_token = "";
        HttpClient httpclient = new DefaultHttpClient();
        String responseBody = "";
        try {
            HttpPost httppost = new HttpPost("https://api.twitter.com/oauth/request_token");
            httppost.setHeader("Authorization",authorization_header_string);
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            responseBody = httpclient.execute(httppost, responseHandler);
            oauth_token = responseBody.substring(responseBody.indexOf("oauth_token=") + 12, responseBody.indexOf("&oauth_token_secret="));
            System.out.println("responseBody: " + responseBody);

        } catch(ClientProtocolException cpe)  {  System.out.println(cpe.getMessage());  }
        catch(IOException ioe) {   System.out.println(ioe.getMessage());  }
        finally { httpclient.getConnectionManager().shutdown();  }

		// encode key/value pairs in a results map
		HashMap<String, String> result = new HashMap<String, String>();

		// parse the response
		StringTokenizer responseBodyTokenizer = new StringTokenizer(responseBody, AMPERSAND);
		String keyValue = null;
		if (responseBodyTokenizer.countTokens() == 3) {
			while (responseBodyTokenizer.hasMoreTokens()) {
				keyValue = responseBodyTokenizer.nextToken();
				// split key and value
				StringTokenizer keyValueTokenizer = new StringTokenizer(keyValue, EQUALS);
				if (keyValueTokenizer.countTokens() == 2) {
					String key = keyValueTokenizer.nextToken();
					String value = keyValueTokenizer.nextToken();
					result.put(key, value);
				} else {
					logger.error(responseBody);
					throw new TwitterException("Response body has unexpected format");
				}
			}
		} else {
			logger.error(responseBody);
			throw new TwitterException("Response body has unexpected format");
		}

		// check the correct values exist
		if (result.containsKey(OAH_TOKEN) && result.containsKey(OAH_TOKEN_SECRET) && result.containsKey(OAH_CALLBACK_CONFIRMED)) {
			return result;
		} else {
			throw new TwitterException("Response body missing expected values");
		}
	}

	/*
	 * Generate Authorisation Endpoint URL
	 */
	public static String getAuthorisationURL(Map<String, String> requestTokenResponse) {
		StringBuffer urlBuffer = new StringBuffer();
		urlBuffer.append(TWITTER_AUTHENTICATION_ENDPOINT);
		urlBuffer.append(QUESTION_MARK);
		urlBuffer.append(OAH_TOKEN);
		urlBuffer.append(EQUALS);
		urlBuffer.append(requestTokenResponse.get(OAH_TOKEN));
		return urlBuffer.toString();
	}

	/*
	 * sign in with twitter step 2 - convert request token to access token
	 */
	public static HashMap<String, String> requestTokenToAccessToken(String oauthToken, String oauthVerifier) throws TwitterException {

		String _numberUsedOnce = generateNumberUsedOnce();
		String _timeStamp= currentTimeInSeconds();

		String oauthSignature = null;

		// signature parameters
		HashMap<String, String> signatureParameters = new HashMap<String, String>();
		signatureParameters.put(OAH_CONSUMER_KEY, TwitterCredentials.TWITTER_LOGIN_CONSUMER_KEY);
		signatureParameters.put(OAH_NONCE, _numberUsedOnce);
		signatureParameters.put(OAH_TIMESTAMP, _timeStamp);
		// include token in signature parameters too
		signatureParameters.put(OAH_TOKEN, oauthToken);
		// include body parameter in the signature Parameters too
		signatureParameters.put(OAH_VERIFIER, oauthVerifier);

		// generate the signature
		try {
			// signing secret not known at this point
			oauthSignature = generateOauthSignature(signatureParameters, TWITTER_ACCESS_TOKEN_ENDPOINT,
					TwitterCredentials.TWITTER_LOGIN_CONSUMER_SECRET, null, METHOD_POST);
		} catch (Exception e) {
			throw new TwitterException(e);
		}

		// authorisation header parameters, excludes verifier parameter
		HashMap<String, String> authorisationParameters = new HashMap<String, String>();
		authorisationParameters.put(OAH_CONSUMER_KEY, TwitterCredentials.TWITTER_SERVICES_CONSUMER_KEY);
		authorisationParameters.put(OAH_NONCE, _numberUsedOnce);
		authorisationParameters.put(OAH_TIMESTAMP, _timeStamp);
		// include access token
		authorisationParameters.put(OAH_TOKEN, oauthToken);
		// exclude verifier, actually sent in the body
		String authHeader = generateOauthHeader(authorisationParameters, oauthSignature);
		
		// generate the request parameters and body
		HashMap<String, String> bodyParameters = new HashMap<String, String>();
		bodyParameters.put(OAH_VERIFIER, oauthVerifier);
		String requestBody = assembleRequestBody(bodyParameters);

		// make the HTTP request
		String responseBody = makeHttpRequest(TWITTER_ENDPOINT_HOST, TWITTER_ACCESS_TOKEN_ENDPOINT_PATH,
				authHeader, requestBody, METHOD_POST);
		logger.info(responseBody);

		// encode key/value pairs in a results map
		HashMap<String, String> result = new HashMap<String, String>();

		// parse the response
		StringTokenizer responseBodyTokenizer = new StringTokenizer(responseBody, AMPERSAND);
		// returns oauth_token, oauth_token_secret, user_id, and screen_name
		String keyValue = null;
		if (responseBodyTokenizer.countTokens() == 4) {
			while (responseBodyTokenizer.hasMoreTokens()) {
				keyValue = responseBodyTokenizer.nextToken();
				// split key and value
				StringTokenizer keyValueTokenizer = new StringTokenizer(keyValue, EQUALS);
				if (keyValueTokenizer.countTokens() == 2) {
					String key = keyValueTokenizer.nextToken();
					String value = keyValueTokenizer.nextToken();
					result.put(key, value);
				} else {
					logger.error(responseBody);
					throw new TwitterException("Response body has unexpected format");
				}
			}
		} else {
			logger.error(responseBody);
			throw new TwitterException("Response body has unexpected format");
		}

		// check the correct values present
		if (result.containsKey(OAH_TOKEN) && result.containsKey(OAH_TOKEN_SECRET) && result.containsKey(TWITTER_USER_ID)
				&& result.containsKey(TWITTER_SCREEN_NAME)) {
			return result;
		} else {
			logger.error(responseBody);
			throw new TwitterException("Response body missing expected values");
		}
	}
}
