package com.chinasofti.Jwt.entity;

import org.jose4j.jwk.JsonWebKey;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

/**
 * Manage the cache of Json Web Keys.
 */
public class KeyCacheManager {

    /**
     * Store JsonWebKey in this HashMap.
     */
    private static HashMap<String, KeyWithTTL> keyList = new HashMap<>();

    /**
     * The live time for JsonWebKey.
     */
    private static int liveMinutes = 20;

    /**
     * Add the JsonWebKey cache
     *
     * @param cacheKeyName
     * @param jsonWebKeys
     * @return
     */
    public static boolean addCache(String cacheKeyName, List<JsonWebKey> jsonWebKeys) {
        KeyWithTTL keyWithTTL = new KeyWithTTL();
        keyWithTTL.setKeys(jsonWebKeys);
        // prepare the cache item expiration time
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.MINUTE, liveMinutes);
        keyWithTTL.setExpirationDate(calendar.getTime());
        keyList.put(cacheKeyName, keyWithTTL);
        return true;
    }

    /**
     * Delete the JsonWebKey cache information
     *
     * @param cacheKeyName
     * @return
     */
    public static boolean delCache(String cacheKeyName) {
        keyList.remove(cacheKeyName);
        return true;
    }

    /**
     * Gets the JsonWebKey cache information
     *
     * @param cacheKeyName
     * @return
     */
    public static List<JsonWebKey> getCache(String cacheKeyName) {
        KeyWithTTL keyWithTTL = keyList.get(cacheKeyName);
        return keyWithTTL != null ? keyWithTTL.getKeys() : null;
    }

    /**
     * Clear expired JsonWebKey cache information
     */
    public static void clearData() {
        HashMap<String, KeyWithTTL> keyListCopy = (HashMap<String, KeyWithTTL>) keyList.clone();
        for (String key : keyListCopy.keySet()) {
            KeyWithTTL jsonWebKey = keyList.get(key);
            if (jsonWebKey.getExpirationDate() == null || new Date().after(jsonWebKey.getExpirationDate())) {
                keyList.remove(key);
            }
        }
    }
}
