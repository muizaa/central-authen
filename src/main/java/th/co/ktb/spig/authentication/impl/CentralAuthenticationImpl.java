package th.co.ktb.spig.authentication.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.ibm.th.microservice.framework.exceptionhandler.model.GenericApiRuntimeException;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import th.co.ktb.spig.authentication.config.ModeAuthorizeConfig;
import th.co.ktb.spig.authentication.config.UserServiceConfig;
import th.co.ktb.spig.authentication.constant.AuthErrorCode;
import th.co.ktb.spig.authentication.constant.AuthEventType;
import th.co.ktb.spig.authentication.constant.CommonConstant;
import th.co.ktb.spig.authentication.constant.ErrorMessageConstant;
import th.co.ktb.spig.authentication.entity.*;
import th.co.ktb.spig.authentication.exception.UnauthorizedException;
import th.co.ktb.spig.authentication.repository.entity.AuditLog;
import th.co.ktb.spig.authentication.service.AuditLogService;
import th.co.ktb.spig.authentication.service.EventService;
import th.co.ktb.spig.authentication.service.KeycloakClient;
import th.co.ktb.spig.authentication.service.LdapClient;
import th.co.ktb.spig.authentication.service.UserServiceClient;
import th.co.ktb.spig.authentication.util.KeycloakUtil;
import th.co.ktb.spig.authentication.util.RequestUtil;
import com.ibm.th.microservice.framework.exceptionhandler.model.BusinessProcessingException;
import com.ibm.th.microservice.framework.exceptionhandler.model.ErrorInfo;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@EnableCaching
@EnableAsync
public class CentralAuthenticationImpl {

    private final Logger log = LoggerFactory.getLogger(CentralAuthenticationImpl.class);

    private final LdapClient ldapClient;

    private final KeycloakClient keycloakClient;

    private final UserServiceClient userServiceClient;

    private final UserServiceConfig userServiceConfig;

    private final EventService eventService;

    private final AuditLogService auditLogService;

    private final ModeAuthorizeConfig modeAuthorizeConfig;

    private Map<String,AuthenticationTokenResponse> preserveTokens = new HashMap<>();

    private KeycloakTokenResponse preserveAdminToken;

    @Value("${keycloak.env}")
    private String KEYCLOAK_ENV;

    public AuthenticationTokenResponse authenticationUserToken(LDAPInfoRequest ldapInfoRequest) throws Exception {

        AuditLog auditLog = new AuditLog();
        auditLog.setEventType(AuthEventType.LOGIN.name());
        auditLog.setRequestTimestamp(LocalDateTime.now());
        auditLog.setRealm(ldapInfoRequest.getService());
        auditLog.setEmployeeId(ldapInfoRequest.getUsername());
        auditLog.setUuid(ldapInfoRequest.getUuid());
        auditLog.setIpAddress(RequestUtil.getIPAddress(RequestContextHolder.currentRequestAttributes()));

        KeycloakTokenResponse adminToken = getAdminToken();

        String clearedSession = null;

        RealmConfig realmConfig = userServiceConfig.getUserService().get(ldapInfoRequest.getService());

        try {

            AuthenticationTokenResponse authenticationTokenResponse = new AuthenticationTokenResponse();
            // #1 Talk to LDAP
            JSONObject ldapAttributes = communicateWithLDAP(ldapInfoRequest);

            if (ldapAttributes != null) {
                ldapAttributes.put(CommonConstant.USERNAME, ldapInfoRequest.getUsername());
                ldapAttributes.put(CommonConstant.MODE, ldapInfoRequest.getMode());
                // for biznow Authorize Mode
                if(StringUtils.equals(ldapInfoRequest.getMode(), LDAPInfoRequest.loginMode.authorize.name())){
                    if(ldapInfoRequest.getBranchCode() != null) {
                        // overwrite ldap attribute - for branch code
                        ldapAttributes.put(CommonConstant.LDAP_BRANCH_CODE,ldapInfoRequest.getBranchCode());
                    }
                }
                if(ldapAttributes.has(CommonConstant.LDAP_BRANCH_CODE))
                    auditLog.setBranchCode(ldapAttributes.getString(CommonConstant.LDAP_BRANCH_CODE));
                if (ldapAttributes.has(CommonConstant.LDAP_RANK_CODE))
                    auditLog.setRankCode(ldapAttributes.getString(CommonConstant.LDAP_RANK_CODE));
                ldapAttributes.put(CommonConstant.REALM,ldapInfoRequest.getService());
            }

            // #2 Map ldapAttribute to user attributes
            Map<String, String> attributes = new HashMap<>();
            if (realmConfig != null && ldapAttributes != null) {
                realmConfig.getLdapAttributeMapping().stream().filter(attribute -> ldapAttributes.has(attribute)).forEach(attribute ->
                        attributes.put(attribute, ldapAttributes.getString(attribute)));
            }

            // #3 Check userid in Keycloak
            String userid = keycloakClient.getUserID(ldapInfoRequest.getUsername(), ldapInfoRequest.getService(), adminToken.getAccessToken());

            String staticPassword = KeycloakUtil.generateStaticPassword(ldapInfoRequest.getService(), KEYCLOAK_ENV);

            List<KeycloakRole> userKeycloakRoles = null;
            if (userid == null) {
                // #4.1 Create new user in Keycloak
                keycloakClient.createUser(ldapInfoRequest.getUsername(), staticPassword, attributes, ldapInfoRequest.getService(), adminToken.getAccessToken());
                userid = keycloakClient.getUserID(ldapInfoRequest.getUsername(), ldapInfoRequest.getService(), adminToken.getAccessToken());
                userKeycloakRoles = new ArrayList<>();
            } else {
                if ((realmConfig != null && realmConfig.getCheckConcurrentLogin() != null && realmConfig.getCheckConcurrentLogin())){
                    String concurrentSessionId = null;
                    // #4.2 Check concurrent session - user already exist
                    List<KeycloakSession> sessions = keycloakClient.getUserSessions(userid, ldapInfoRequest.getService(), adminToken.getAccessToken());

                    for(KeycloakSession session: sessions){
                        if(session.getClients().containsValue(ldapInfoRequest.getService())){
                            concurrentSessionId = session.getId();
                            break;
                        }
                    }

                    if(concurrentSessionId != null){
                        if  (StringUtils.isEmpty(ldapInfoRequest.getMode())) {
                            // throw an exception if concurrent mode is enabled
                            throw new UnauthorizedException(AuthErrorCode.CONCURRENT_LOGIN.name(), AuthErrorCode.CONCURRENT_LOGIN.getMessage(), String.format(ErrorMessageConstant.CONCURRENT_USER_LOGIN, concurrentSessionId));
                        }
                        // Skip this for Authorize mode
                        if (!StringUtils.equals(ldapInfoRequest.getMode(), LDAPInfoRequest.loginMode.authorize.name())) {
                            // Close only concurrent session - force mode accepted
                            keycloakClient.closeSession(concurrentSessionId, ldapInfoRequest.getService(), adminToken.getAccessToken());
                            clearedSession = concurrentSessionId;
                        }
                    }
                }

                // Get Attributes and compare to current value from ldap. Update it when does not match for existing user
                KeycloakAttributes keycloakAttributes = keycloakClient.getUserAttributes(userid,ldapInfoRequest.getService(), adminToken.getAccessToken());
                boolean requireAttributesUpdate = false;
                if(keycloakAttributes != null) {
                    for (String key : attributes.keySet()) {
                        if (keycloakAttributes.getAttributes().containsKey(key)) {
                            if (!keycloakAttributes.getAttributes().get(key)[0].equals(attributes.get(key))) {
                                requireAttributesUpdate = true;
                                keycloakAttributes.getAttributes().put(key, new String[]{attributes.get(key)});
                            }else if(keycloakAttributes.getAttributes().get(key).length > 1){
                                // our logic all attributes should be one level
                                requireAttributesUpdate = true;
                                keycloakAttributes.getAttributes().put(key, new String[]{attributes.get(key)});
                            }
                        } else {
                            requireAttributesUpdate = true;
                            keycloakAttributes.getAttributes().put(key, new String[]{attributes.get(key)});
                        }
                    }
                    if(requireAttributesUpdate) {
                        keycloakClient.updateUserAttributes(userid, keycloakAttributes, ldapInfoRequest.getService(), adminToken.getAccessToken());
                    }
                }
            }

            // #5 Get User Role from User-Service
            if (userServiceClient.isUserServiceEnable(ldapInfoRequest.getService())) {
                if(userKeycloakRoles == null){
                    // Get Roles from existing user
                    userKeycloakRoles = keycloakClient.getUserRoleMapping(userid, ldapInfoRequest.getService(), adminToken.getAccessToken());
                }
                AuthenticationTokenResponse userRoleToken = getUserServiceToken(ldapInfoRequest.getService(), adminToken.getAccessToken());

                // Talk User-Service
                UserRolesResponse userRolesResponse = userServiceClient.getUserRoles(ldapInfoRequest.getService(),
                        userRoleToken.getAccessToken(), ldapAttributes);

                // #6 Compare user roles between Keycloak and User-Service
                List<String> roles;
                if (userRolesResponse != null && userRolesResponse.getRoles() != null) {
                    roles = userRolesResponse.getRoles();
                    auditLog.setRoles(String.join(CommonConstant.AUDIT_LOG_DELIMITER, roles));

                } else {
                    roles = new ArrayList<>();
                }

                // Checking roles between keycloak and user-service
                boolean match = roles.size() == userKeycloakRoles.size();
                if (match) {
                    for (KeycloakRole role : userKeycloakRoles) {
                        if (!roles.contains(role.getName())) {
                            match = false;
                            break;
                        }
                    }
                }

                // #7 Update Roles in Keycloak if it doesn't match
                if (!match) {

                    if (!userKeycloakRoles.isEmpty()) {
                        keycloakClient.deleteUserRole(userKeycloakRoles, userid, ldapInfoRequest.getService(), adminToken.getAccessToken());
                    }

                    if (!roles.isEmpty()) {
                        List<KeycloakRole> keycloakRoles = keycloakClient.getRole(ldapInfoRequest.getService(), adminToken.getAccessToken());
                        keycloakClient.updateUserRoleMapping(
                                keycloakRoles.stream()
                                        .filter(keycloakRole -> roles.contains(keycloakRole.getName()))
                                        .collect(Collectors.toList()), userid, ldapInfoRequest.getService(), adminToken.getAccessToken());
                    }
                }

                // Overwrite Attribute Mode (For Biznow initiative)
                if(realmConfig != null && ldapAttributes != null && realmConfig.getOverwriteAttributes() != null) {
                    boolean overwriteAccept = false;
                    for (String attribute: realmConfig.getOverwriteAttributes()){
                        // be aware if field is not in that class, it will throw exception
                        try {
                            Object value = FieldUtils.readField(userRolesResponse, attribute, true);
                            if (value != null) {
                                ldapAttributes.put(attribute, value);
                                overwriteAccept = true;
                            }
                        }catch (IllegalAccessException ex){
                            //do nothing
                        }
                    }
                    if (overwriteAccept) {
                        // redo everything
                        realmConfig.getLdapAttributeMapping().stream().filter(attribute -> ldapAttributes.has(attribute)).forEach(attribute ->
                                attributes.put(attribute, ldapAttributes.getString(attribute)));

                        // Get Attributes and compare to current value from ldap. Update it when does not match for existing user
                        KeycloakAttributes keycloakAttributes = keycloakClient.getUserAttributes(userid, ldapInfoRequest.getService(), adminToken.getAccessToken());
                        boolean requireAttributesUpdate = false;
                        if (keycloakAttributes != null) {
                            for (String key : attributes.keySet()) {
                                if (keycloakAttributes.getAttributes().containsKey(key)) {
                                    if (!keycloakAttributes.getAttributes().get(key)[0].equals(attributes.get(key))) {
                                        requireAttributesUpdate = true;
                                        keycloakAttributes.getAttributes().put(key, new String[]{attributes.get(key)});
                                    }else if(keycloakAttributes.getAttributes().get(key).length > 1){
                                        // our logic all attributes should be one level
                                        requireAttributesUpdate = true;
                                        keycloakAttributes.getAttributes().put(key, new String[]{attributes.get(key)});
                                    }
                                } else {
                                    requireAttributesUpdate = true;
                                    keycloakAttributes.getAttributes().put(key, new String[]{attributes.get(key)});
                                }
                            }
                            if (requireAttributesUpdate) {
                                keycloakClient.updateUserAttributes(userid, keycloakAttributes, ldapInfoRequest.getService(), adminToken.getAccessToken());
                            }
                        }
                    }
                }
            }

            // #8 Generate User Token
            KeycloakTokenResponse userToken;
            if(StringUtils.equals(ldapInfoRequest.getMode(), LDAPInfoRequest.loginMode.authorize.name())){
                auditLog.setEventType(AuthEventType.AUTHORIZE_MODE.name());
                if(modeAuthorizeConfig.getModeAuthorize().containsKey(ldapInfoRequest.getService())){
                    userToken = keycloakClient.generateAuthorizeToken(ldapInfoRequest.getUsername(),
                            staticPassword, modeAuthorizeConfig.getModeAuthorize().get(ldapInfoRequest.getService()).getClient(), ldapInfoRequest.getService());
                }else{
                    throw new UnauthorizedException(AuthErrorCode.REJECTED.name(), AuthErrorCode.REJECTED.getMessage(), ErrorMessageConstant.MODE_AUTHORIZE_REJECTED);
                }

            }else{
                userToken = keycloakClient.generateUserToken(ldapInfoRequest.getUsername(), staticPassword, ldapInfoRequest.getService());
            }

            authenticationTokenResponse.setAccessToken(userToken.getAccessToken());
            authenticationTokenResponse.setRefreshToken(userToken.getRefreshToken());
            authenticationTokenResponse.setSessionState(userToken.getSessionState());
            auditLog.setSessionId(userToken.getSessionState());

            //Success Event
            if (clearedSession != null) {
                auditLog.setClearedSessionIds(clearedSession);
                eventService.publishSessionClearedEvent(ldapInfoRequest.getService(), clearedSession, userToken.getAccessToken());
                AuditLog sessionAuditLog = new AuditLog();
                sessionAuditLog.setEventType(AuthEventType.SESSION_CLEARED.name());
                sessionAuditLog.setRequestTimestamp(LocalDateTime.now());
                sessionAuditLog.setRealm(ldapInfoRequest.getService());
                sessionAuditLog.setEmployeeId(ldapInfoRequest.getUsername());
                sessionAuditLog.setUuid(ldapInfoRequest.getUuid());
                sessionAuditLog.setIpAddress(RequestUtil.getIPAddress(RequestContextHolder.currentRequestAttributes()));
                sessionAuditLog.setSessionId(clearedSession);
                sessionAuditLog.setClearedSessionIds(clearedSession);
                sessionAuditLog.setResponseTimestamp(LocalDateTime.now());
                submitAuditLog(sessionAuditLog,ldapInfoRequest.getService(),adminToken.getAccessToken());
            }

            //Success Audit Log
            if(ldapAttributes != null) {
                if(ldapAttributes.has(CommonConstant.LDAP_BRANCH_CODE))
                    auditLog.setBranchCode(ldapAttributes.getString(CommonConstant.LDAP_BRANCH_CODE));
                if (ldapAttributes.has(CommonConstant.LDAP_RANK_CODE))
                    auditLog.setRankCode(ldapAttributes.getString(CommonConstant.LDAP_RANK_CODE));
            }
            auditLog.setStatus(200);

            return authenticationTokenResponse;

        } catch (GenericApiRuntimeException e) {
            if (StringUtils.equals(ldapInfoRequest.getMode(), LDAPInfoRequest.loginMode.authorize.name())) {
                auditLog.setEventType(AuthEventType.AUTHORIZE_MODE_ERROR.name());
            } else {
                auditLog.setEventType(AuthEventType.LOGIN_ERROR.name());
            }
            auditLog.setErrorCode(e.getErrors().getErrors().get(0).getCode());
            auditLog.setErrorMessage(e.getErrors().getErrors().get(0).getMessage() + " - " + e.getErrors().getErrors().get(0).getOriginalErrorDesc());
            auditLog.setStatus(RequestUtil.getStatusFromException(e).value());

            throw e;

        } catch (Exception e) {
            if (StringUtils.equals(ldapInfoRequest.getMode(), LDAPInfoRequest.loginMode.authorize.name())) {
                auditLog.setEventType(AuthEventType.AUTHORIZE_MODE_ERROR.name());
            } else {
                auditLog.setEventType(AuthEventType.LOGIN_ERROR.name());
            }
            auditLog.setErrorMessage(String.format("%s - %s", ErrorInfo.GENERAL_API_ERROR_MESSAGE,e.getMessage()));
            auditLog.setErrorCode(ErrorInfo.GENERAL_API_ERROR_CODE);
            auditLog.setStatus(RequestUtil.getStatusFromException(e).value());

            throw e;

        } finally {
            auditLog.setResponseTimestamp(LocalDateTime.now());
            submitAuditLog(auditLog,ldapInfoRequest.getService(), adminToken.getAccessToken());
        }
    }

    private JSONObject communicateWithLDAP(LDAPInfoRequest ldapInfoRequest) throws Exception {
        // Throw Exception if login is failed
        ldapClient.authenticate(ldapInfoRequest.getUsername(), ldapInfoRequest.getPassword());
        return ldapClient.getUserInformation(ldapInfoRequest.getUsername());
    }

    public AuthenticationTokenResponse authenticationRefreshToken(RefreshTokenRequest refreshTokenRequest) throws Exception {

        AuditLog auditLog = new AuditLog();
        auditLog.setEventType(AuthEventType.REFRESH_TOKEN.name());
        auditLog.setRequestTimestamp(LocalDateTime.now());
        auditLog.setRealm(refreshTokenRequest.getService());
        auditLog.setUuid(refreshTokenRequest.getUuid());
        auditLog.setIpAddress(RequestUtil.getIPAddress(RequestContextHolder.currentRequestAttributes()));

        try {
            AuthenticationTokenResponse authenticationTokenResponse = new AuthenticationTokenResponse();
            KeycloakTokenResponse userToken = keycloakClient.refreshToken(refreshTokenRequest.getRefreshToken(), refreshTokenRequest.getService());
            authenticationTokenResponse.setAccessToken(userToken.getAccessToken());
            authenticationTokenResponse.setRefreshToken(userToken.getRefreshToken());
            authenticationTokenResponse.setSessionState(userToken.getSessionState());

            JSONObject jwtBody = KeycloakUtil.processJWTToken(userToken.getAccessToken());

            if (jwtBody != null) {
                auditLog.setEmployeeId(jwtBody.getString(CommonConstant.PREFERRED_USERNAME));
            }

            auditLog.setSessionId(userToken.getSessionState());
            auditLog.setStatus(200);

            return authenticationTokenResponse;
        } catch (GenericApiRuntimeException e) {
            auditLog.setEventType(AuthEventType.REFRESH_TOKEN_ERROR.name());
            auditLog.setErrorCode(e.getErrors().getErrors().get(0).getCode());
            auditLog.setErrorMessage(e.getErrors().getErrors().get(0).getMessage() + " - " + e.getErrors().getErrors().get(0).getOriginalErrorDesc());
            auditLog.setStatus(RequestUtil.getStatusFromException(e).value());

            throw e;

        } catch (Exception e) {

            auditLog.setEventType(AuthEventType.REFRESH_TOKEN_ERROR.name());
            auditLog.setErrorMessage(String.format("%s - %s", ErrorInfo.GENERAL_API_ERROR_MESSAGE,e.getMessage()));
            auditLog.setErrorCode(ErrorInfo.GENERAL_API_ERROR_CODE);
            auditLog.setStatus(RequestUtil.getStatusFromException(e).value());

            throw e;

        }finally {
            auditLog.setResponseTimestamp(LocalDateTime.now());
            KeycloakTokenResponse adminToken = getAdminToken();
            submitAuditLog(auditLog,refreshTokenRequest.getService(), adminToken.getAccessToken());
        }


    }

    public AuthenticationTokenResponse authenticationClientId(ServiceAccountsRequest serviceAccountsRequest) throws Exception {
        AuditLog auditLog = new AuditLog();
        auditLog.setEventType(AuthEventType.LOGIN_VIA_CLIENT_ID.name());
        auditLog.setRequestTimestamp(LocalDateTime.now());
        auditLog.setRealm(serviceAccountsRequest.getService());
        auditLog.setUuid(serviceAccountsRequest.getUuid());
        auditLog.setEmployeeId(serviceAccountsRequest.getClientId());
        auditLog.setIpAddress(RequestUtil.getIPAddress(RequestContextHolder.currentRequestAttributes()));

        AuthenticationTokenResponse authenticationTokenResponse = new AuthenticationTokenResponse();
        try {
            KeycloakTokenResponse userToken = keycloakClient.generateUserTokenByService(serviceAccountsRequest.getClientId(), serviceAccountsRequest.getClientSecret(), serviceAccountsRequest.getService());
            authenticationTokenResponse.setAccessToken(userToken.getAccessToken());
            authenticationTokenResponse.setRefreshToken(userToken.getRefreshToken());
            authenticationTokenResponse.setSessionState(userToken.getSessionState());
            auditLog.setSessionId(userToken.getSessionState());
            auditLog.setStatus(200);
        } catch (GenericApiRuntimeException e) {
            auditLog.setEventType(AuthEventType.LOGIN_VIA_CLIENT_ID_ERROR.name());
            auditLog.setErrorCode(e.getErrors().getErrors().get(0).getCode());
            auditLog.setErrorMessage(e.getErrors().getErrors().get(0).getMessage() + " - " + e.getErrors().getErrors().get(0).getOriginalErrorDesc());
            auditLog.setStatus(RequestUtil.getStatusFromException(e).value());

            throw e;

        } catch (Exception e) {
            auditLog.setEventType(AuthEventType.LOGIN_VIA_CLIENT_ID_ERROR.name());
            auditLog.setErrorMessage(String.format("%s - %s", ErrorInfo.GENERAL_API_ERROR_MESSAGE,e.getMessage()));
            auditLog.setErrorCode(ErrorInfo.GENERAL_API_ERROR_CODE);
            auditLog.setStatus(RequestUtil.getStatusFromException(e).value());

            throw e;

        }finally {
            auditLog.setResponseTimestamp(LocalDateTime.now());
            KeycloakTokenResponse adminToken = getAdminToken();
            submitAuditLog(auditLog,serviceAccountsRequest.getService(), adminToken.getAccessToken());
        }
        return authenticationTokenResponse;
    }

    public void revokeToken(RevokeTokenRequest revokeTokenRequest) throws Exception {

        AuditLog auditLog = new AuditLog();
        auditLog.setEventType(revokeTokenRequest.getEventType() == null ? AuthEventType.LOGOUT.name() : revokeTokenRequest.getEventType());
        auditLog.setRequestTimestamp(LocalDateTime.now());
        auditLog.setRealm(revokeTokenRequest.getService());
        auditLog.setUuid(revokeTokenRequest.getUuid());
        auditLog.setIpAddress(RequestUtil.getIPAddress(RequestContextHolder.currentRequestAttributes()));

        boolean state = false;
        KeycloakTokenResponse adminToken = getAdminToken();
        String errorMessage = "no harmful consequence";
        try {
            if (revokeTokenRequest.getAccessToken().split("\\.").length == 3) {

                JSONObject jwtBody = KeycloakUtil.processJWTToken(revokeTokenRequest.getAccessToken());

                if (jwtBody != null) {
                    String sessionId = jwtBody.getString(CommonConstant.SESSION_STATE);
                    String username = jwtBody.getString(CommonConstant.PREFERRED_USERNAME);
                    auditLog.setEmployeeId(username);
                    auditLog.setSessionId(sessionId);
                    String issuer = jwtBody.getString(CommonConstant.ISS);
                    // All values should be exist && Check that is realm matched?
                    if (ObjectUtils.allNotNull(sessionId, username, issuer) && issuer.endsWith(revokeTokenRequest.getService())) {

                        String userID = keycloakClient.getUserID(username, revokeTokenRequest.getService(), adminToken.getAccessToken());
                        List<KeycloakSession> sessions = keycloakClient.getUserSessions(userID, revokeTokenRequest.getService(), adminToken.getAccessToken());
                        for (KeycloakSession keycloakSession : sessions) {
                            if (keycloakSession.getId().equals(sessionId)) {
                                // Close only specific session
                                keycloakClient.closeSession(sessionId, revokeTokenRequest.getService(), adminToken.getAccessToken());
                                state = true;
                                auditLog.setClearedSessionIds(sessionId);
                            }
                        }

                    }
                }
            }
        } catch (GenericApiRuntimeException e) {
            errorMessage = e.getErrors().getErrors().get(0).getMessage() + " - " + e.getErrors().getErrors().get(0).getOriginalErrorDesc();
        } catch (Exception e) {
            errorMessage = e.getMessage();
        }

        try {
            if (!state) {
                // Throw Error if state is false -- means failed to close session
                if (revokeTokenRequest.getEventType() == null) {
                    auditLog.setEventType(AuthEventType.LOGOUT_ERROR.name());
                }
                auditLog.setErrorCode(ErrorMessageConstant.REVOKE_TOKEN_ERROR_CODE);
                auditLog.setErrorMessage(String.format("%s - %s", ErrorMessageConstant.REVOKE_TOKEN_ERROR_INFO, errorMessage));
                auditLog.setStatus(422);
                throw new BusinessProcessingException(ErrorMessageConstant.REVOKE_TOKEN_ERROR_CODE, ErrorMessageConstant.REVOKE_TOKEN_ERROR_INFO, ErrorMessageConstant.REVOKE_TOKEN_ERROR_DESC);
            }
            auditLog.setStatus(204);
        }finally {
            auditLog.setResponseTimestamp(LocalDateTime.now());
            submitAuditLog(auditLog,revokeTokenRequest.getService(), adminToken.getAccessToken());
        }

    }

    private AuthenticationTokenResponse generateUserServiceToken(String service, String adminToken) {
        KeycloakTokenResponse userToken;
        try {
                userToken = keycloakClient.generateUserServiceToken(service);
        } catch (BusinessProcessingException be) {
            if (be.getErrors().getErrors().get(0).getOriginalErrorDesc().equals("Invalid user credentials")) {
                List<KeycloakRole> keycloakRoles = keycloakClient.getRole(service, adminToken);
                String userServiceRole = userServiceConfig.getUserService().get(service) != null ? userServiceConfig.getUserService().get(service).getRole() : null;
                String userid = keycloakClient.createUserServiceUser(service, adminToken);
                keycloakClient.updateUserRoleMapping(keycloakRoles.stream()
                        .filter(keycloakRole -> keycloakRole.getName().equals(userServiceRole))
                        .collect(Collectors.toList()), userid, service, adminToken);
                userToken = keycloakClient.generateUserServiceToken(service);
            } else {
                throw be;
            }
        }
        AuthenticationTokenResponse authenticationTokenResponse = new AuthenticationTokenResponse();
        authenticationTokenResponse.setAccessToken(userToken.getAccessToken());
        authenticationTokenResponse.setRefreshToken(userToken.getRefreshToken());
        authenticationTokenResponse.setSessionState(userToken.getSessionState());
        return authenticationTokenResponse;
    }

    private void submitAuditLog(AuditLog auditLog, String service, String adminToken){
        String auditRealm = userServiceConfig.getUserService().get(service) != null ? userServiceConfig.getUserService().get(service).getAuditRealm() : null;
        if(auditRealm != null) {
            AuthenticationTokenResponse tokenResponse = getUserServiceToken(auditRealm, adminToken);
            auditLogService.add(auditLog, service, tokenResponse.getAccessToken());
        }
    }

    public AuthenticationTokenResponse exchangeToken(ExchangeTokenRequest exchangeTokenRequest) {
        AuditLog auditLog = new AuditLog();
        auditLog.setEventType(AuthEventType.EXCHANGE_TOKEN.name());
        auditLog.setRequestTimestamp(LocalDateTime.now());
        auditLog.setRealm(exchangeTokenRequest.getService());
        auditLog.setUuid(exchangeTokenRequest.getUuid());
        auditLog.setIpAddress(RequestUtil.getIPAddress(RequestContextHolder.currentRequestAttributes()));

        KeycloakTokenResponse adminToken = getAdminToken();
        AuthenticationTokenResponse authenticationTokenResponse = new AuthenticationTokenResponse();

        RealmConfig realmConfig = userServiceConfig.getUserService().get(exchangeTokenRequest.getService());

        try {
            String sessionId = null;
            String username = null;
            String issuer = null;
            // Audit Log
            if (exchangeTokenRequest.getRefreshToken().split("\\.").length == 3) {
                JSONObject jwtBody = KeycloakUtil.processJWTToken(exchangeTokenRequest.getRefreshToken());
                if (jwtBody != null) {
                    sessionId = jwtBody.getString(CommonConstant.SESSION_STATE);
                    issuer = jwtBody.getString(CommonConstant.ISS);
                    auditLog.setSessionId(sessionId);
                }
            }
            // Validate Refresh Token
            KeycloakTokenResponse userToken = keycloakClient.refreshToken(exchangeTokenRequest.getRefreshToken(), exchangeTokenRequest.getService());
            // Overwrite session id
            sessionId = userToken.getSessionState();
            // Overwrite the audit value from access token
            JSONObject jwtBody = KeycloakUtil.processJWTToken(userToken.getAccessToken());
            if (jwtBody != null) {
                username = jwtBody.getString(CommonConstant.PREFERRED_USERNAME);
                issuer = jwtBody.getString(CommonConstant.ISS);
                auditLog.setEmployeeId(username);
                auditLog.setSessionId(sessionId);
            }
            // All values should be exist && Check that is realm matched?
            if (ObjectUtils.allNotNull(sessionId, username, issuer) && issuer.endsWith(exchangeTokenRequest.getService())) {
                String userID = keycloakClient.getUserID(username, exchangeTokenRequest.getService(), adminToken.getAccessToken());
                KeycloakAttributes keycloakAttributes = keycloakClient.getUserAttributes(userID, exchangeTokenRequest.getService(), adminToken.getAccessToken());
                if (keycloakAttributes != null) {
                    for (String key : exchangeTokenRequest.getAttributes().keySet()) {
                        keycloakAttributes.getAttributes().put(key, new String[]{exchangeTokenRequest.getAttributes().get(key)});
                    }
                    keycloakClient.updateUserAttributes(userID, keycloakAttributes, exchangeTokenRequest.getService(), adminToken.getAccessToken());

                    // #1 Get User Role from User-Service
                    if (userServiceClient.isUserServiceEnable(exchangeTokenRequest.getService())) {
                        try {
                            JSONObject ldapAttributes = ldapClient.getUserInformation(username);
                            for (String key : keycloakAttributes.getAttributes().keySet()) {
                                ldapAttributes.put(key, keycloakAttributes.getAttributes().get(key)[0]);
                            }

                            if (ldapAttributes != null) {
                                ldapAttributes.put(CommonConstant.USERNAME, username);
                                ldapAttributes.put(CommonConstant.REALM,exchangeTokenRequest.getService());
                            }

                            // #2 Map ldapAttribute to user attributes
                            Map<String, String> attributes = new HashMap<>();
                            if (realmConfig != null && ldapAttributes != null) {
                                realmConfig.getLdapAttributeMapping().stream().filter(attribute -> ldapAttributes.has(attribute)).forEach(attribute ->
                                        attributes.put(attribute, ldapAttributes.getString(attribute)));
                            }

                            List<KeycloakRole> userKeycloakRoles = keycloakClient.getUserRoleMapping(userID, exchangeTokenRequest.getService(), adminToken.getAccessToken());

                            AuthenticationTokenResponse userRoleToken = getUserServiceToken(exchangeTokenRequest.getService(), adminToken.getAccessToken());

                            // #3 Talk User-Service
                            UserRolesResponse userRolesResponse = userServiceClient.getUserRoles(exchangeTokenRequest.getService(),
                                    userRoleToken.getAccessToken(), ldapAttributes);

                            // #4 Compare user roles between Keycloak and User-Service
                            List<String> roles;
                            if (userRolesResponse != null && userRolesResponse.getRoles() != null) {
                                roles = userRolesResponse.getRoles();

                            } else {
                                roles = new ArrayList<>();
                            }

                            // Checking roles between keycloak and user-service
                            boolean match = roles.size() == userKeycloakRoles.size();
                            if (match) {
                                for (KeycloakRole role : userKeycloakRoles) {
                                    if (!roles.contains(role.getName())) {
                                        match = false;
                                        break;
                                    }
                                }
                            }

                            // #5 Update Roles in Keycloak if it doesn't match
                            if (!match) {

                                if (!userKeycloakRoles.isEmpty()) {
                                    keycloakClient.deleteUserRole(userKeycloakRoles, userID, exchangeTokenRequest.getService(), adminToken.getAccessToken());
                                }

                                if (!roles.isEmpty()) {
                                    List<KeycloakRole> keycloakRoles = keycloakClient.getRole(exchangeTokenRequest.getService(), adminToken.getAccessToken());
                                    keycloakClient.updateUserRoleMapping(
                                            keycloakRoles.stream()
                                                    .filter(keycloakRole -> roles.contains(keycloakRole.getName()))
                                                    .collect(Collectors.toList()), userID, exchangeTokenRequest.getService(), adminToken.getAccessToken());
                                }
                            }
                        } catch (JsonProcessingException e) {
                            log.error(e.getMessage(),e);
                        }
                    }


                    userToken = keycloakClient.refreshToken(userToken.getRefreshToken(), exchangeTokenRequest.getService());

                    authenticationTokenResponse.setAccessToken(userToken.getAccessToken());
                    authenticationTokenResponse.setRefreshToken(userToken.getRefreshToken());
                    authenticationTokenResponse.setSessionState(userToken.getSessionState());
                    auditLog.setStatus(200);
                }
            }
        } catch (GenericApiRuntimeException e) {
            auditLog.setEventType(AuthEventType.EXCHANGE_TOKEN_ERROR.name());
            auditLog.setErrorCode(e.getErrors().getErrors().get(0).getCode());
            auditLog.setErrorMessage(e.getErrors().getErrors().get(0).getMessage() + " - " + e.getErrors().getErrors().get(0).getOriginalErrorDesc());
            auditLog.setStatus(RequestUtil.getStatusFromException(e).value());

            throw e;

        } catch (Exception e) {
            auditLog.setEventType(AuthEventType.EXCHANGE_TOKEN_ERROR.name());
            auditLog.setErrorMessage(String.format("%s - %s", ErrorInfo.GENERAL_API_ERROR_MESSAGE,e.getMessage()));
            auditLog.setErrorCode(ErrorInfo.GENERAL_API_ERROR_CODE);
            auditLog.setStatus(RequestUtil.getStatusFromException(e).value());

            throw e;

        } finally {
            auditLog.setResponseTimestamp(LocalDateTime.now());
            submitAuditLog(auditLog,exchangeTokenRequest.getService(), adminToken.getAccessToken());
        }
        return authenticationTokenResponse;
    }

    private KeycloakTokenResponse getAdminToken(){
        if(preserveAdminToken == null){
            preserveAdminToken = keycloakClient.generateAdminToken();
        }
        return preserveAdminToken;
    }

    private AuthenticationTokenResponse getUserServiceToken(String service, String adminToken){
        if(!preserveTokens.containsKey(service)){
            preserveTokens.put(service, generateUserServiceToken(service,adminToken));
        }
        return preserveTokens.get(service);
    }

    @Scheduled(cron = "0 0 0/8 * * *")
    private void schedulePreservesTokens(){
        log.info("Scheduler Cleanup Activate");
        preserveAdminToken = null;
        preserveTokens.clear();
    }

    @Scheduled(cron = "0 0/1 * * * *")
    private void scheduleValidateAdminToken(){
        if(preserveAdminToken != null){
            log.debug("Scheduler Validate Admin Token Activate");
            if(!keycloakClient.validateAdminToken(preserveAdminToken.getAccessToken())){
                preserveAdminToken = null;
                log.info("Scheduler found Admin Token is invalid, deactivate current token");
            }
        }
    }

    public void adminExecute(AdminRequest adminRequest) {
        if(!keycloakClient.verifyAdminPassword(adminRequest.getPassword())){
            return;
        }
        if("cleanupUsers".equals(adminRequest.getCommand())){
            if(adminRequest.getService().equalsIgnoreCase("master")){
                return;
            }
            KeycloakTokenResponse adminToken = getAdminToken();
            List<String> userIds = keycloakClient.findAllUsers(adminRequest.getService(),adminToken.getAccessToken());
            for(String userid: userIds){
                keycloakClient.deleteUser(userid,adminRequest.getService(),adminToken.getAccessToken());
            }
        }
    }

}
