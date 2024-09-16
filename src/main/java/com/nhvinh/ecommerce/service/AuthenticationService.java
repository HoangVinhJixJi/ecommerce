package com.nhvinh.ecommerce.service;

import com.nhvinh.ecommerce.dto.AuthenticationRequest;
import com.nhvinh.ecommerce.dto.IntrospectRequest;
import com.nhvinh.ecommerce.dto.LogoutRequest;
import com.nhvinh.ecommerce.dto.RefreshRequest;
import com.nhvinh.ecommerce.dto.AuthenticationResponse;
import com.nhvinh.ecommerce.dto.IntrospectResponse;
import com.nhvinh.ecommerce.entity.InvalidatedToken;
import com.nhvinh.ecommerce.entity.User;
import com.nhvinh.ecommerce.exception.CustomException;
import com.nhvinh.ecommerce.exception.ErrorCode;
import com.nhvinh.ecommerce.repository.InvalidatedTokenRepository;
import com.nhvinh.ecommerce.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.StringJoiner;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class AuthenticationService {

    UserRepository userRepository;
    private final InvalidatedTokenRepository invalidatedTokenRepository;

    @NonFinal
    @Value("${jwt.signerKey}")
    protected String SIGNER_KEY;
    @NonFinal
    @Value("${jwt.valid-duration}")
    protected long VALID_DURATION;
    @NonFinal
    @Value("${jwt.refreshable-duration}")
    protected long REFRESHABLE_DURATION;

    public AuthenticationResponse authenticate(AuthenticationRequest request){
        log.info("SignerKey: {}", SIGNER_KEY);
        var user = userRepository.findByUsername(request.getUsername()).orElseThrow(()-> new CustomException(ErrorCode.USER_NOT_EXISTED));

        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);

        boolean authenticated =  passwordEncoder.matches(request.getPassword(), user.getPassword());
        if(!authenticated){
            throw new CustomException(ErrorCode.UNAUTHENTICATED);
        }
        var token = generateToken(user);
        return  AuthenticationResponse.builder()
                .authenticated(true)
                .token(token)
                .build();

    }

    public void logout(LogoutRequest request) throws ParseException, JOSEException {
        try {
            var signToken = verifyToken(request.getToken(), false);
            String jit = signToken.getJWTClaimsSet().getJWTID();
            Date expiryTime = signToken.getJWTClaimsSet().getExpirationTime();
            InvalidatedToken invalidatedToken = InvalidatedToken.builder()
                    .id(jit)
                    .expiryTime(expiryTime)
                    .build();
            invalidatedTokenRepository.save(invalidatedToken);
        }
        catch (CustomException e){
            log.error("Token already expired");
        }


    }

    public AuthenticationResponse refreshToken(RefreshRequest request) throws ParseException, JOSEException {
        var signedJWT = verifyToken(request.getToken(), true);
        String jit = signedJWT.getJWTClaimsSet().getJWTID();
        Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        InvalidatedToken invalidatedToken = InvalidatedToken.builder()
                .id(jit)
                .expiryTime(expiryTime)
                .build();
        invalidatedTokenRepository.save(invalidatedToken);
        var username = signedJWT.getJWTClaimsSet().getSubject();
        var user = userRepository.findByUsername(username)
                .orElseThrow(()->new CustomException(ErrorCode.USER_NOT_EXISTED));
        var token = generateToken(user);
        return AuthenticationResponse.builder()
                .authenticated(true)
                .token(token)
                .build();

    }

    private SignedJWT verifyToken(String token, boolean isRefresh) throws ParseException, JOSEException {
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());
        SignedJWT signedJWT = SignedJWT.parse(token);
        Date expirationDate = (isRefresh) ?
                new Date(signedJWT.getJWTClaimsSet().getIssueTime().toInstant()
                        .plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS).toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();;
        boolean verified = signedJWT.verify(verifier);
        boolean isValid = verified && expirationDate != null && expirationDate.after(new Date());
        if(!isValid){
            throw new CustomException(ErrorCode.UNAUTHORIZED);
        }
        if(invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID()))
            throw new CustomException(ErrorCode.UNAUTHENTICATED);
        return signedJWT;
    }

    private String generateToken(User user){
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer("NHVinh")
                .issueTime(new Date())
                .expirationTime(new Date(Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .claim("firstName", user.getFirstName())
                .build();
        Payload payload = new Payload(jwtClaimsSet.toJSONObject());
        JWSObject jwsObject = new JWSObject(header, payload);
        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Cannot create token" , e);
            throw new RuntimeException(e);
        }

    }

    public IntrospectResponse introspect(IntrospectRequest request) throws JOSEException, ParseException {
        if (request == null || request.getToken() == null ) {
            throw new IllegalArgumentException("Request, token cannot be null");
        }
        var token = request.getToken();
        boolean isValid = true;
        try {
            verifyToken(token, false);
        }
        catch (CustomException e){
            isValid = false;
        }
        return IntrospectResponse.builder()
                .valid(isValid)
                .build();

    }

    private String buildScope(User user){
        StringJoiner stringJoiner = new StringJoiner(" ");
        if(!CollectionUtils.isEmpty(user.getRoles())){
            user.getRoles().forEach(role -> {
                stringJoiner.add("ROLE_" + role.getName());
                if(!CollectionUtils.isEmpty(role.getPermissions())){
                    role.getPermissions().forEach(
                            permission -> {
                                stringJoiner.add(permission.getName());
                            }
                    );
                }

            });
        }
        log.info("===> scope in JWT:  {} ",stringJoiner.toString());
        return stringJoiner.toString();
    }

    //Delete InvalidateToken in table if expiryTime are expired
    public void cleanInvalidatedTokenTable() {
        log.info("Starting cleanup of invalidated token table");

        List<InvalidatedToken> expiredTokens = invalidatedTokenRepository.findAll()
                .stream()
                .filter(invalidatedToken -> invalidatedToken.getExpiryTime().before(new Date()))
                .collect(Collectors.toList());

        if (!expiredTokens.isEmpty()) {
            invalidatedTokenRepository.deleteAll(expiredTokens);
            log.info("Deleted {} expired tokens from the invalidated token table", expiredTokens.size());
        } else {
            log.info("No expired tokens found to delete");
        }
    }
}

