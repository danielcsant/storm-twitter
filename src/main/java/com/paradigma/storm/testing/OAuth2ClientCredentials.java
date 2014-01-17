package com.paradigma.storm.testing;

/**
 * OAuth 2 credentials found in the <a href="http://www.dailymotion.com/profile/developer">
 * Developer Profile Page</a>.
 *
 * <p>
 * Once at the Developer Profile page, you will need to create a Daily Motion account if you do not
 * already have one. Click on "Create a new API Key". Enter "http://127.0.0.1:8080/Callback" under
 * "Callback URL" and select "Native Application" under "Application Profile". Enter a port number
 * other than 8080 if that is what you intend to use.
 * </p>
 *
 * @author Ravi Mistry
 */
public class OAuth2ClientCredentials {

    /** Value of the "API Key". */
    public static final String API_KEY = "261184202-nC17ym8tHLCbxpNG28WGx7rVSf3IY8gmBpHPxoGH";

    /** Value of the "API Secret". */
    public static final String API_SECRET = "KzptuRsCaN4dWvvtVHYHEmv6W7YgSeQ1MjBdCwaTh4Rym";

    /** Port in the "Callback URL". */
    public static final int PORT = 8080;

    /** Domain name in the "Callback URL". */
    public static final String DOMAIN = "127.0.0.1";

    public static void errorIfNotSpecified() {
        if (API_KEY.startsWith("Enter ") || API_SECRET.startsWith("Enter ")) {
            System.out.println(
                    "Enter API Key and API Secret from http://www.dailymotion.com/profile/developer"
                            + " into API_KEY and API_SECRET in " + OAuth2ClientCredentials.class);
            System.exit(1);
        }
    }
}