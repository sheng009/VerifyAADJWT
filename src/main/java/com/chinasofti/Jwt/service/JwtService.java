package com.chinasofti.Jwt.service;

import com.alibaba.fastjson.JSONObject;
import com.chinasofti.Jwt.constraint.CacheKeysConstraint;
import com.chinasofti.Jwt.constraint.CommonConstraint;
import com.chinasofti.Jwt.entity.AADJWTModel;
import com.chinasofti.Jwt.entity.KeyCacheManager;
import com.chinasofti.Jwt.entity.KeyWithTTL;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.*;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;


@Service

public class JwtService {

    private KeyCacheManager keyCacheManager;

    private KeyWithTTL keyWithTTL;

    private AADJWTModel aadjwtModel;

    private JwtClaims jwtClaims;

    private Boolean skipDefaultAudienceValidation = false;

    private Boolean requirSubject = false;

    private Boolean requireJwtId = false;

    public List<JsonWebKey> GetSigningKeys(String clientID, String tenantID, String jwksUrl) {
        List<JsonWebKey> keys = null;
        HttpsJwks httpsJkws = new HttpsJwks(jwksUrl);
        try {
            keys = httpsJkws.getJsonWebKeys();
        } catch (Exception e) {
            e.printStackTrace();
            keys = null;
        }

        String cacheKey = CacheKeysConstraint.SIGNING_KEYS.replace("[tenantId]", tenantID)
                .replace("[clientId]", clientID);
        // Successed to get public key
        if (keys != null) {
            KeyCacheManager.addCache(cacheKey, keys);
        } else {
            keys = KeyCacheManager.getCache(cacheKey);
        }

        return keys;
    }

    private JwtConsumerBuilder GetJwtConsumerBuilder() {
        JwtConsumerBuilder customJwtConsumerBuilder = new JwtConsumerBuilder()
                .setSkipAllDefaultValidators();
        if (!skipDefaultAudienceValidation) {
            //Set<String> setAud = Collections.emptySet();
            Set<String> setAud = new HashSet<String>();
            setAud.add("api://faa0afb8-bfe5-4648-82e9-c6f3b909fcf4");
            customJwtConsumerBuilder = customJwtConsumerBuilder.registerValidator(new AudValidator(setAud, false));
        }
        customJwtConsumerBuilder = customJwtConsumerBuilder.registerValidator(new IssValidator(null, false))
                .registerValidator(new SubValidator(requirSubject))
                .registerValidator(new JtiValidator(requireJwtId));

        return customJwtConsumerBuilder;
    }

    public Boolean Verify(String token, String tenantID, List<JsonWebKey> jsonWebKeys) throws MalformedClaimException {
        Boolean isValid = false;
        JwksVerificationKeyResolver keyResolver = new JwksVerificationKeyResolver(jsonWebKeys);
        JwtConsumer jwtConsumer = GetJwtConsumerBuilder()
                .setVerificationKeyResolver(keyResolver)
                .setAllowedClockSkewInSeconds(30)
                .setExpectedIssuer("https://sts.windows.net/" + tenantID + "/")
                .setExpectedAudience(CommonConstraint.EXPECTED_AUDIENCE)
                .setJwsAlgorithmConstraints(
                        AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256)
                .build();
        try {
            //  Validate the JWT and process it to the Claims
            jwtClaims = jwtConsumer.processToClaims(token);
            isValid = true;
            System.out.println("JWT validation succeeded! " + jwtClaims);
        } catch (InvalidJwtException e) {
            // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
            // Hopefully with meaningful explanations(s) about what went wrong.
            System.out.println("Invalid JWT! " + e);

            // Programmatic access to (some) specific reasons for JWT invalidity is also possible
            // should you want different error handling behavior for certain conditions.
            if (e.hasExpired()) {
                System.out.println("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
            }
            // Or maybe the audience was invalid
            if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
                System.out.println("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
            }
        }
        return isValid;
    }

    /**
     * get jwks_uri from OpenID Connect metadata document
     *
     * @param stsDiscoveryEndpoint
     * @return jwks_uri
     */
    public String GetJWKS(String stsDiscoveryEndpoint, String jwksUrlKey) {
        HttpClient client = new HttpClient();
        String res = "";
        String jwks_uri = "";
        GetMethod getMethod = new GetMethod(stsDiscoveryEndpoint);
        try {
            int code = client.executeMethod(getMethod);
            if (code == 200) {
                res = getMethod.getResponseBodyAsString();
                System.out.println(res);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (StringUtils.isNotEmpty(res)) {
            JSONObject jsonObject = JSONObject.parseObject(res);
            jwks_uri = String.valueOf(jsonObject.get(jwksUrlKey));
        }
        return jwks_uri;
    }


    /**
     * Validate JWT Expiration Time
     * @param expirationTime Original expiration time
     * @param extraValidityDay Extended validity period
     * @return Boolean
     */
    public Boolean ValidateJWTExpirationTime(Long expirationTime, int extraValidityDay) {
        //  long expirationTimeSeconds = Long.parseLong(expirationTime);
        Date time = new Date((long) expirationTime * 1000);
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(time);
        calendar.add(Calendar.DATE, extraValidityDay);
        time = calendar.getTime();

        if (time.compareTo(new Date()) > 0) {

            return true;
        }
        return false;
    }


    /**
     * Get a claim from the JWT
     * @param claimType
     * @return
     * @throws MalformedClaimException
     */
    public Long GetClaim(String claimType) throws MalformedClaimException {
        return jwtClaims.getClaimValue(claimType, Long.class);
    }
}