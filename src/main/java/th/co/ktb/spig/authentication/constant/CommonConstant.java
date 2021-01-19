package th.co.ktb.spig.authentication.constant;

public class CommonConstant {

    public static final String LDAP_USERNAME = "%s@%s";
    public static final String LDAP_SAMACCOUNTNAME= "sAMAccountName=%s";
    public static final String LDAP_USERNAME_PRINCIPLENAME = "userPrincipalName="+LDAP_USERNAME;
    public static final String LDAP_DOMAIN = "OU=KTBUsers";


    public static final String BEARER_TOKEN = "Bearer %s";
    public static final String KEYCLOAK_GENERATE_TOKEN_ENDPOINT = "%s/auth/realms/%s/protocol/openid-connect/token";
    public static final String KEYCLOAK_GET_USERINFO_ENDPOINT = "%s/auth/admin/realms/%s/users?username=%s";
    public static final String KEYCLOAK_CREATE_USER_ENDPOINT = "%s/auth/admin/realms/%s/users";
    public static final String KEYCLOAK_LOGOUT_USER_ENDPOINT = "%s/auth/admin/realms/%s/users/%s/logout";
    public static final String KEYCLOAK_LOGOUT_SESSION_ENDPOINT = "%s/auth/admin/realms/%s/sessions/%s";
    public static final String KEYCLOAK_RESET_PASSWORD_USER_ENDPOINT = "%s/auth/admin/realms/%s/users/%s/reset-password";
    public static final String KEYCLOAK_GET_USER_SESSIONS_ENDPOINT = "%s/auth/admin/realms/%s/users/%s/sessions";
    public static final String KEYCLOAK_GET_ROLE_ENDPOINT = "%s/auth/admin/realms/%s/roles";
    public static final String KEYCLOAK_USER_ROLE_MAPPING_ENDPOINT = "%s/auth/admin/realms/%s/users/%s/role-mappings/realm";
    public static final String KEYCLOAK_USER_ROLE_MAPPING_ASSIGNED_ENDPOINT = "%s/auth/admin/realms/%s/users/%s/role-mappings/realm/composite";
    public static final String KEYCLOAK_USER_ATTRIBUTES_ENDPOINT = "%s/auth/admin/realms/%s/users/%s";
    public static final String KEYCLOAK_GROUPS_COUNT_ENDPOINT = "%s/auth/admin/realms/%s/groups/count";


    public static final String KEYCLOAK_BODY_TOKEN_GRANT_TYPE = "grant_type";
    public static final String KEYCLOAK_BODY_TOKEN_USERNAME = "username";
    public static final String KEYCLOAK_BODY_TOKEN_PASSWORD = "password";
    public static final String KEYCLOAK_BODY_TOKEN_CLIENT_ID = "client_id";
    public static final String KEYCLOAK_BODY_TOKEN_CLIENT_SECRET = "client_secret";
    public static final String KEYCLOAK_BODY_TOKEN_REFRESH_TOKEN = "refresh_token";
    public static final String KEYCLOAK_BODY_CREDENTIAL_TYPE_PASSWORD = "password";
    public static final String KEYCLOAK_BODY_CREDENTIAL_CLIENT_USER_SERVICE_SUFFIX = "-authen";

    public static final String KEYCLOAK_BODY_TOKEN_GRANT_TYPE_PASSWORD = "password";
    public static final String KEYCLOAK_BODY_TOKEN_GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String KEYCLOAK_BODY_TOKEN_GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    public static final String KEYCLOAK_BODY_RESET_PASSWORD_TYPE = "password";

    public static final String PREFERRED_USERNAME = "preferred_username";
    public static final String SESSION_STATE = "session_state";
    public static final String ISS = "iss";

    public static final String USERNAME = "username";
    public static final String PASSWORD_STATIC = "%s%s%s";
    public static final String PASSWORD_ALLOWANCE_ASCII = "!@#$%^&*?:;";

    public static final String LDAP_BRANCH_CODE = "kcsbranchcode";
    public static final String LDAP_RANK_CODE = "rankcode";
    public static final String MODE = "mode";
    public static final String REALM = "realm";

    public static final String AUDIT_LOG_DELIMITER = ",";

    /*LDAP Error Code*/
    public static final String USER_NOT_FOUND="525";
    public static final String INVALID_CREDENTIAL="52e";
    public static final String NOT_PERMIT_LOGON="530";
    public static final String NOT_PERMIT_LOGON_WORKSTATION="531";
    public static final String PASSWORD_EXPIRED="532";
    public static final String ACCOUNT_DISABLED="533";
    public static final String USER_NOT_BE_GRANTED="534";
    public static final String ACCOUNT_EXPIRED="701";
    public static final String USER_MUST_RESET="773";
    public static final String USER_LOCKED="775";

    /*AUTHORIZE JWT*/
    public static final String AUTHORIZE_JWT_ISS = "central-authentication";
    public static final String AUTHORIZE_JWT_AZP = "central-authentication";

}
