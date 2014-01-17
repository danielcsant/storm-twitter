package com.paradigma.tweeter;

import java.util.HashMap;

/**
 * Created with IntelliJ IDEA.
 * User: dcarroza
 * Date: 17/01/14
 * Time: 10:23
 * To change this template use File | Settings | File Templates.
 */
public class TwitterCallback {

    private static String OAH_TOKEN = "s0L8uUecyzr1RbG4fCipaBqU7EJ9slmyEILCleys8";
    private static String OAH_VERIFIER = "9191362";

    public static void main(String[] args) throws Exception{
        twitterCallBack();
        TwitterServices.getMentions();
    }

    private static void twitterCallBack() {
        HashMap<String, String> accessTokenValues = null;
        try {
            accessTokenValues = TwitterServices.requestTokenToAccessToken(OAH_TOKEN, OAH_VERIFIER);
        } catch (TwitterException te) {
            te.printStackTrace();
        }

        System.out.println(accessTokenValues.get(TwitterServices.OAH_TOKEN));
        System.out.println(accessTokenValues.get(TwitterServices.OAH_TOKEN_SECRET));
        System.out.println(accessTokenValues.get(TwitterServices.TWITTER_SCREEN_NAME));
        System.out.println(accessTokenValues.get(TwitterServices.TWITTER_USER_ID));
    }

}
