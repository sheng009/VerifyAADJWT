package com.chinasofti.Jwt.entity;

import org.jose4j.jwk.JsonWebKey;

import java.util.Date;
import java.util.HashMap;
import java.util.List;

public class KeyCacheManager {

    /**
     * 用户信息缓存
     */
    private static HashMap<String, KeyWithTTL> keyList = new HashMap<>();

    /**
     * 保存时间
     */
    private static int liveTime = 60;

    /**
     * 添加用户信息缓存
     *
     * @param cacheKeyName
     * @param jsonWebKeys
     * @return
     */
    public static boolean addCache(String cacheKeyName, List<JsonWebKey> jsonWebKeys) {
        KeyWithTTL keyWithTTL = new KeyWithTTL();
        keyWithTTL.setKeys(jsonWebKeys);
        keyWithTTL.setExpirationDate(new Date());
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
        for (String key : keyList.keySet()) {
            KeyWithTTL jsonWebKey = keyList.get(key);
            if (jsonWebKey.getExpirationDate() == null || new Date().after(jsonWebKey.getExpirationDate())) {
                keyList.remove(key);
            }
        }
    }

}
