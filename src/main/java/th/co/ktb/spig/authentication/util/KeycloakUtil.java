package th.co.ktb.spig.authentication.util;


import th.co.ktb.spig.authentication.constant.CommonConstant;
import org.apache.commons.lang3.RandomStringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.HttpStatusCodeException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;

public class KeycloakUtil {

    private static final Logger log = LoggerFactory.getLogger(KeycloakUtil.class);

    private KeycloakUtil() {
        throw new AssertionError();
    }

    public static String generateRandomPassword() {
        Random random = new Random();
        String alphanumeric = RandomStringUtils.randomAlphanumeric(10, 30);
        String alphanumeric2 = RandomStringUtils.randomAlphanumeric(10, 30);
        String ascii = RandomStringUtils.random(random.nextInt(10) + 5, CommonConstant.PASSWORD_ALLOWANCE_ASCII);
        return alphanumeric.concat(ascii).concat(alphanumeric2);
    }

    public static String generateStaticPassword(String service, String env) {
        return String.format(CommonConstant.PASSWORD_STATIC, service, env.toUpperCase(), CommonConstant.PASSWORD_ALLOWANCE_ASCII);
    }

    public static JSONObject processJWTToken(String token) {

        int header = token.indexOf('.');
        int lastDot = token.lastIndexOf('.');
        String body = token.substring(header + 1, lastDot);
        // Fix bug - https://stackoverflow.com/questions/28584080/base64-java-lang-illegalargumentexception-illegal-character
        body = body.replace('-', '+').replace('_', '/');
        byte[] decoded = Base64.getDecoder().decode(body);
        try {
            String output = new String(decoded, StandardCharsets.UTF_8);
            return new JSONObject(output);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    public static String getKeyCloakErrorCode(HttpStatusCodeException exception) {
        try {
            JSONObject error = new JSONObject(exception.getResponseBodyAsString());
            return error.getString("error");
        } catch (Exception e) {
            return exception.getMessage();
        }
    }

    public static String getKeyCloakErrorDescription(HttpStatusCodeException exception) {
        try {
            JSONObject error = new JSONObject(exception.getResponseBodyAsString());
            return error.getString("error_description");
        } catch (Exception e) {
            return exception.getResponseBodyAsString();
        }
    }
}
