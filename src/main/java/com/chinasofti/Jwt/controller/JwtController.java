package com.chinasofti.Jwt.controller;

import com.chinasofti.Jwt.constraint.CommonConstraint;
import com.chinasofti.Jwt.entity.AADJWTModel;
import com.chinasofti.Jwt.entity.Result;
import com.chinasofti.Jwt.service.JwtService;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.MalformedClaimException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Controller
@RequestMapping("/api/jwt")
public class JwtController {
    @Autowired
    JwtService jwtService;

    @ResponseBody
    @RequestMapping("/checkAADJWT")
    public Result checkAADJWT(AADJWTModel aadjwtModel) throws MalformedClaimException {
        Result result = new Result();
        String estimate = aadjwtModel.estimate();
        if (StringUtils.isNotEmpty(estimate)) {
            result.status = false;
            result.message = estimate;
            return result;
        }
        String jwksUri = jwtService.GetJWKS(CommonConstraint.STS_DISCOVERY_ENDPOINT.replace("{tenantId}", aadjwtModel.getTenantId()), "jwks_uri");
        List<JsonWebKey> signingKeys = jwtService.GetSigningKeys(aadjwtModel.getClientId(), aadjwtModel.getTenantId(), jwksUri);
        if (signingKeys == null) {
            result.status = false;
            result.message = "Token validation failed. You can try it again later.";
            return result;
        }

        Boolean isValidity = jwtService.Verify(aadjwtModel.getToken(), aadjwtModel.getTenantId(), signingKeys);
        if (!isValidity) {
            result.message = "Token is not vaild";
            result.status = isValidity;
        } else {
            if (!jwtService.ValidateJWTExpirationTime(jwtService.GetClaim("exp", Long.class), 1)) {
                result.message = "Token is expired";
                result.status = false;
            } else {
                result.message = "Token is vaild";
                result.status = true;
            }
        }

        return result;
    }


}
