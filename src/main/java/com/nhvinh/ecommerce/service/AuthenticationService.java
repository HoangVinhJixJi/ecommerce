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
        log.info("function  authenticate in AuthenticationService");
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

    public void logout(LogoutRequest request) {
        log.info("function logout in AuthenticationService");
        try {
            var signToken = verifyToken(request.getToken(), false);  // Xác thực token
            String jit = signToken.getJWTClaimsSet().getJWTID();  // Lấy JWT ID (jit)
            Date expiryTime = signToken.getJWTClaimsSet().getExpirationTime();  // Lấy thời gian hết hạn

            // Kiểm tra xem token đã bị vô hiệu hóa trước đó chưa
            if (invalidatedTokenRepository.existsById(jit)) {
                log.info("Token already invalidated");
                return; // Dừng nếu token đã bị vô hiệu hóa
            }

            // Tạo đối tượng token vô hiệu hóa và lưu vào database
            InvalidatedToken invalidatedToken = InvalidatedToken.builder()
                    .id(jit)
                    .expiryTime(expiryTime)
                    .build();
            invalidatedTokenRepository.save(invalidatedToken);
            log.info("Token invalidated successfully");

        } catch (CustomException e) {
            log.error("Token already expired or invalid: ", e);
            throw new CustomException(ErrorCode.TOKEN_EXPIRED_OR_INVALID);
        } catch (ParseException | JOSEException e) {
            log.error("Error in parsing or verifying token: ", e);
            throw new RuntimeException("Failed to parse or verify token");
        }
    }


    public AuthenticationResponse refreshToken(RefreshRequest request) throws ParseException, JOSEException {
        log.info("function  refresh token in AuthenticationService");
        // Xác thực và kiểm tra token
        var signedJWT = verifyToken(request.getToken(), true);

        // Kiểm tra nếu token đã bị vô hiệu hóa
        String jit = signedJWT.getJWTClaimsSet().getJWTID();
        if (invalidatedTokenRepository.existsById(jit)) {
            log.info("Token already invalidated: (invalidatedTokenRepository.existsById(jit)");
            throw new CustomException(ErrorCode.TOKEN_EXPIRED_OR_INVALID);
        }
        // Kiểm tra thời hạn sống của refresh token
        Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();

        //Thêm vào bảng invalidated_token để biết token này đã logout
        InvalidatedToken invalidatedToken =
                InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

        invalidatedTokenRepository.save(invalidatedToken);

        // Xác định người dùng từ refresh token
        var username = signedJWT.getJWTClaimsSet().getSubject();
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_EXISTED));

        // Sinh access token mới
        var token = generateToken(user);
        return AuthenticationResponse.builder()
                .authenticated(true)
                .token(token)
                .build();

    }

    private SignedJWT verifyToken(String token, boolean isRefresh) throws ParseException, JOSEException {
        log.info("function  verify token in AuthenticationService");
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());
        SignedJWT signedJWT = SignedJWT.parse(token);
        Date expirationDate = (isRefresh) ?
                new Date(signedJWT.getJWTClaimsSet().getIssueTime().toInstant()
                        .plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS).toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();
        boolean verified = signedJWT.verify(verifier);
        boolean isValid = verified && expirationDate != null && expirationDate.after(new Date());
        log.info("verified: {}", verified);
        log.info("expirationDate: {}", expirationDate != null);
        log.info("expirationDate.after(new Date()): {} ", expirationDate.after(new Date()));

        if(!isValid){
            log.info("is not Valid ");
            throw new CustomException(ErrorCode.UNAUTHORIZED);
        }

        if(invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID())) {
            log.info(" check token in table invalidated token ");
            throw new CustomException(ErrorCode.UNAUTHENTICATED);
        }
        return signedJWT;
    }

    private String generateToken(User user){
        log.info("function  generateToken in AuthenticationService");
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
        log.info("function  introspect in AuthenticationService");
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

    private String buildScope(User user) throws CustomException{
        log.info("function  buildScope in AuthenticationService");
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
        }else {
            log.info("CollectionUtils.isEmpty(user.getRoles()) is empty");
        }
        log.info("===> scope in JWT:  {} ###",stringJoiner.toString());
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

