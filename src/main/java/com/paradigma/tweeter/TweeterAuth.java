package com.paradigma.tweeter;

import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * Created with IntelliJ IDEA.
 * User: dcarroza
 * Date: 15/01/14
 * Time: 17:57
 * To change this template use File | Settings | File Templates.
 */
public class TweeterAuth {



    public static void main(String[] args) {

        Map<String, String> requestTokenValues = null;

        // get a twitter request token
        try {
            requestTokenValues = TwitterServices.getRequestToken();
        } catch (TwitterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // Redirect to authentication URL
        String authenticationUrl = TwitterServices.getAuthorisationURL(requestTokenValues);

        openBrowserToAuthorizate(authenticationUrl);

        String pin = getPinFromUserInput();

        twitterCallBack(requestTokenValues.get(TwitterServices.OAH_TOKEN), pin);
    }

    private static String getPinFromUserInput() {
        Scanner reader = new Scanner(System.in);
        System.out.println("Introduce el PIN:");
        //get user input for a
        return reader.nextLine();
    }

    private static void openBrowserToAuthorizate(String authenticationUrl) {
        try {
            Desktop desktop= Desktop.getDesktop();
            desktop.browse(new URI(authenticationUrl));
        } catch (IOException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (URISyntaxException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }

    private static void twitterCallBack(String oahToken, String oahVerifier) {
        HashMap<String, String> accessTokenValues = null;
        try {
            accessTokenValues = TwitterServices.requestTokenToAccessToken(oahToken, oahVerifier);
        } catch (TwitterException te) {
            te.printStackTrace();
        }

        System.out.println(accessTokenValues.get(TwitterServices.OAH_TOKEN));
        System.out.println(accessTokenValues.get(TwitterServices.OAH_TOKEN_SECRET));
        System.out.println(accessTokenValues.get(TwitterServices.TWITTER_SCREEN_NAME));
        System.out.println(accessTokenValues.get(TwitterServices.TWITTER_USER_ID));
    }

}
