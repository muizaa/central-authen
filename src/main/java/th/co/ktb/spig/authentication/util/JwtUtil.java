package th.co.ktb.spig.authentication.util;

import th.co.ktb.spig.authentication.constant.CommonConstant;
import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;

public class JwtUtil {

    private static final String JWT_HEADER = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

    private static final String HMAC_256 = "HmacSHA256";

    private JwtUtil() {
        throw new AssertionError();
    }

    public static String generateAuthorizeJwt(String username,
                                              String branchCode,
                                              String rankCode,
                                              List<String> roles,
                                              String secret) {
        JSONObject payload = new JSONObject();
        payload.put("azp", CommonConstant.AUTHORIZE_JWT_AZP);
        payload.put("iss", CommonConstant.AUTHORIZE_JWT_ISS);
        payload.put("iat", ZonedDateTime.now().toInstant().getEpochSecond());
        payload.put("exp", ZonedDateTime.now().plusSeconds(60).toInstant().getEpochSecond());
        payload.put("type", "Bearer");
        payload.put("preferred_username", username);
        payload.put("kcsbranchcode", branchCode);
        payload.put("rankcode", rankCode);
        payload.put("roles", roles);

        String signature = hmacSha256(encode(JWT_HEADER.getBytes()) + "." + encode(payload.toString().getBytes()), secret);
        return encode(JWT_HEADER.getBytes()) + "." + encode(payload.toString().getBytes()) + "." + signature;
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String hmacSha256(String data, String secret) {
        try {

            byte[] hash = secret.getBytes(StandardCharsets.UTF_8);

            Mac sha256Hmac = Mac.getInstance(HMAC_256);
            SecretKeySpec secretKey = new SecretKeySpec(hash, HMAC_256);
            sha256Hmac.init(secretKey);

            byte[] signedBytes = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));

            return encode(signedBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            return null;
        }
    }

}
