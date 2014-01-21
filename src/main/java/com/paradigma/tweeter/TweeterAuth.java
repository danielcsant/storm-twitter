package com.paradigma.tweeter;

import twitter4j.Status;
import twitter4j.Twitter;
import twitter4j.TwitterFactory;
import twitter4j.conf.ConfigurationBuilder;

import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
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

        System.out.println("OAH_TOKEN: " + accessTokenValues.get(TwitterServices.OAH_TOKEN));
        System.out.println("OAH_TOKEN_SECRET: " + accessTokenValues.get(TwitterServices.OAH_TOKEN_SECRET));
        System.out.println("TWITTER_SCREEN_NAME: " + accessTokenValues.get(TwitterServices.TWITTER_SCREEN_NAME));
        System.out.println("TWITTER_USER_ID: " + accessTokenValues.get(TwitterServices.TWITTER_USER_ID));

        ConfigurationBuilder cb = new ConfigurationBuilder();
        cb.setDebugEnabled(true)
                .setOAuthConsumerKey(TwitterCredentials.TWITTER_SERVICES_CONSUMER_KEY)
                .setOAuthConsumerSecret(TwitterCredentials.TWITTER_SERVICES_CONSUMER_SECRET)
                .setOAuthAccessToken(accessTokenValues.get(TwitterServices.OAH_TOKEN))
                .setOAuthAccessTokenSecret(accessTokenValues.get(TwitterServices.OAH_TOKEN_SECRET));
        TwitterFactory tf = new TwitterFactory(cb.build());
        Twitter twitter = tf.getInstance();

        try {
            // The factory instance is re-useable and thread safe.
            List<Status> statuses = twitter.getHomeTimeline();
            System.out.println("Showing home timeline.");
            for (Status status : statuses) {
                System.out.println(status.getUser().getName() + ":" +
                        status.getText());
            }
        } catch (twitter4j.TwitterException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }


//        TwitterServices.statusUpdate("Funcionaaa", accessTokenValues.get(TwitterServices.OAH_TOKEN));
    }

}
