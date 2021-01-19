package th.co.ktb.spig.authentication.service;

import th.co.ktb.spig.authentication.constant.CommonConstant;
import th.co.ktb.spig.authentication.entity.*;
import th.co.ktb.spig.authentication.external.KeycloakRestTemplate;
import th.co.ktb.spig.authentication.util.KeycloakUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class KeycloakClient {

    @Autowired
    private KeycloakRestTemplate keycloakRestTemplate;

    @Value("${keycloak.authentication.admin.username}")
    private String ADMIN_USERNAME;

    @Value("${keycloak.authentication.admin.password}")
    private String ADMIN_PASSWORD;

    @Value("${keycloak.authentication.admin.client_id}")
    private String ADMIN_CLIENT_ID;

    @Value("${keycloak.authentication.admin.realm}")
    private String ADMIN_REALM;

    public KeycloakTokenResponse generateAdminToken() {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE,CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE_PASSWORD);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_USERNAME,ADMIN_USERNAME);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_PASSWORD,ADMIN_PASSWORD);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_CLIENT_ID,ADMIN_CLIENT_ID);
        return keycloakRestTemplate.generateNewToken(keycloakRestTemplate.handleEntity(map),ADMIN_REALM);
    }

    public KeycloakTokenResponse generateUserToken(String username, String password, String realm) {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE,CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE_PASSWORD);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_USERNAME,username);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_PASSWORD,password);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_CLIENT_ID,realm);
        return keycloakRestTemplate.generateNewToken(keycloakRestTemplate.handleEntity(map),realm);
    }

    public KeycloakTokenResponse generateAuthorizeToken(String username, String password, String client, String realm) {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE,CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE_PASSWORD);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_USERNAME,username);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_PASSWORD,password);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_CLIENT_ID,client);
        return keycloakRestTemplate.generateNewToken(keycloakRestTemplate.handleEntity(map),realm);
    }

    public KeycloakTokenResponse generateUserServiceToken(String realm) {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE,CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE_PASSWORD);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_USERNAME,ADMIN_USERNAME);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_PASSWORD,ADMIN_PASSWORD);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_CLIENT_ID,realm.concat(CommonConstant.KEYCLOAK_BODY_CREDENTIAL_CLIENT_USER_SERVICE_SUFFIX));
        return keycloakRestTemplate.generateNewToken(keycloakRestTemplate.handleEntity(map),realm);
    }

    public KeycloakTokenResponse generateUserTokenByService(String clientId, String clientSecret, String realm) {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE,CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE_CLIENT_CREDENTIALS);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_CLIENT_ID,clientId);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_CLIENT_SECRET,clientSecret);
        return keycloakRestTemplate.generateNewToken(keycloakRestTemplate.handleEntity(map),realm);
    }

    public KeycloakTokenResponse refreshToken(String refreshToken, String realm) {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE,CommonConstant.KEYCLOAK_BODY_TOKEN_GRANT_TYPE_REFRESH_TOKEN);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_REFRESH_TOKEN,refreshToken);
        map.add(CommonConstant.KEYCLOAK_BODY_TOKEN_CLIENT_ID,realm);
        return keycloakRestTemplate.generateNewToken(keycloakRestTemplate.handleEntity(map),realm);
    }

    public String getUserID(String username, String realm, String tokenBearer){
        return keycloakRestTemplate.getUserIDByUsername(keycloakRestTemplate.handleEntity(tokenBearer),username,realm);
    }

    public boolean createUser(String username, String password, Map<String, String> attributes, String realm, String tokenBearer){
        KeycloakUserReqeust keycloakUserReqeust = new KeycloakUserReqeust();
        keycloakUserReqeust.setUsername(username);
        keycloakUserReqeust.setEnabled("true");
        List<KeycloakCredentials> keycloakCredentials = new ArrayList<>();
        KeycloakCredentials credentials = new KeycloakCredentials();
        credentials.setType(CommonConstant.KEYCLOAK_BODY_CREDENTIAL_TYPE_PASSWORD);
        credentials.setValue(password);
        keycloakCredentials.add(credentials);
        keycloakUserReqeust.setCredentials(keycloakCredentials);
        keycloakUserReqeust.setAttributes(attributes);
        return keycloakRestTemplate.createUser(keycloakRestTemplate.handleEntity(keycloakUserReqeust, tokenBearer),realm);
    }

    public String createUserServiceUser(String realm, String tokenBearer){
        String userid = null;
        if(createUser(ADMIN_USERNAME,ADMIN_PASSWORD,new HashMap<>(),realm,tokenBearer)) {
            userid = keycloakRestTemplate.getUserIDByUsername(keycloakRestTemplate.handleEntity(tokenBearer), ADMIN_USERNAME, realm);
        }
        return userid;
    }

    public boolean closeAllSession(String userid, String realm, String tokenBearer) {
        return keycloakRestTemplate.logoutUser(keycloakRestTemplate.handleEntity(tokenBearer), userid, realm);
    }

    @Deprecated
    public String resetPassword(String userid, String realm, String tokenBearer) throws Exception {
        String newPassword = KeycloakUtil.generateRandomPassword();
        KeycloakResetPasswordRequest keycloakResetPasswordRequest = new KeycloakResetPasswordRequest();
        keycloakResetPasswordRequest.setType(CommonConstant.KEYCLOAK_BODY_RESET_PASSWORD_TYPE);
        keycloakResetPasswordRequest.setValue(newPassword);
        boolean success = keycloakRestTemplate.resetPassword(keycloakRestTemplate.handleEntity(keycloakResetPasswordRequest, tokenBearer),userid,realm);
        if(success){
            return newPassword;
        }
        return null;
        // throw new ResourceConflictException("KEYCLOAK005","Failed to reset password via keycloak", String.format("Unable to reset password for %s on %s",userid,realm));
    }

    @Cacheable(value="keycloakroles",key="#realm")
    public List<KeycloakRole> getRole(String realm, String tokenBearer){
        return keycloakRestTemplate.getRole(keycloakRestTemplate.handleEntity(tokenBearer),realm);
    }

    public boolean deleteUserRole(List<KeycloakRole> keycloakRoles,String userid, String realm, String tokenBearer){
        return keycloakRestTemplate.deleteUserRole(keycloakRestTemplate.handleEntity(keycloakRoles,tokenBearer), userid,realm);
    }

    public boolean updateUserRoleMapping(List<KeycloakRole> keycloakRoles,String userid, String realm, String tokenBearer){
        return keycloakRestTemplate.updateUserRoleMapping(keycloakRestTemplate.handleEntity(keycloakRoles,tokenBearer), userid,realm);
    }

    public List<KeycloakRole> getUserRoleMapping(String userid, String realm, String tokenBearer){
        return keycloakRestTemplate.getUserRoleMapping(keycloakRestTemplate.handleEntity(tokenBearer), userid,realm);
    }

    public List<KeycloakSession> getUserSessions(String userid, String realm, String tokenBearer){
        return keycloakRestTemplate.getUserSessionsByUserID(keycloakRestTemplate.handleEntity(tokenBearer),userid,realm);
    }

    public boolean closeSession(String sessionid, String realm, String tokenBearer){
        return keycloakRestTemplate.logoutSession(keycloakRestTemplate.handleEntity(tokenBearer),sessionid,realm);
    }

    public void closeAdminSession(String sessionid, String tokenBearer){
        try{
            keycloakRestTemplate.logoutSession(keycloakRestTemplate.handleEntity(tokenBearer),sessionid,ADMIN_REALM);
        }catch (Exception e){
            // do nothing;
        }
    }

    public KeycloakAttributes getUserAttributes(String userid, String realm, String tokenBearer){
        return keycloakRestTemplate.getUserAttributes(keycloakRestTemplate.handleEntity(tokenBearer), userid,realm);
    }

    public boolean updateUserAttributes(String userid, KeycloakAttributes attributes, String realm, String tokenBearer){
        return keycloakRestTemplate.updateUserAttributes(keycloakRestTemplate.handleEntity(attributes, tokenBearer), userid,realm);
    }

    public boolean validateAdminToken(String tokenBearer){
        return keycloakRestTemplate.validateAdminToken(keycloakRestTemplate.handleEntity(tokenBearer),ADMIN_REALM);
    }

    public boolean deleteUser(String userid, String realm, String tokenBearer){
        return keycloakRestTemplate.deleteUser(keycloakRestTemplate.handleEntity(tokenBearer), userid,realm);
    }

    public List<String> findAllUsers(String realm, String tokenBearer){
        return keycloakRestTemplate.findAllUsers(keycloakRestTemplate.handleEntity(tokenBearer),realm);
    }

    public boolean verifyAdminPassword(String password){
        return ADMIN_PASSWORD.equals(password);
    }
}
