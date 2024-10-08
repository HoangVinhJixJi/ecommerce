package com.nhvinh.ecommerce.config;

import com.nhvinh.ecommerce.dto.IntrospectRequest;
import com.nhvinh.ecommerce.service.AuthenticationService;
import com.nimbusds.jose.JOSEException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
@Slf4j
@Component
public class CustomJwtDecoder implements JwtDecoder {

    @Value("${jwt.signerKey}")
    private String signerKey;

    @Autowired
    private AuthenticationService authenticationService;
    private NimbusJwtDecoder nimbusJwtDecoder = null;

    @Override
    public Jwt decode(String token) throws JwtException {
        log.info("function decodeJwt in CustomJwtDecoder");
        try {
            log.info("call function introspect in CustomJwtDecoder");
            var response =  authenticationService.introspect(IntrospectRequest.builder().token(token).build());
            if(!response.isValid())
                throw new JwtException("Invalid token");
        }
        catch (JOSEException | ParseException e) {
            throw new JwtException(e.getMessage());
        }
        if (nimbusJwtDecoder == null) {
            SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(), "HS512");
            nimbusJwtDecoder = NimbusJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm(MacAlgorithm.HS512).build();
        }
        return nimbusJwtDecoder.decode(token);
    }
}
