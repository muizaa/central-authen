package th.co.ktb.spig.authentication.constant;

public class ErrorMessageConstant {
    // TOKEN 00x
    public static final String KEYCLOAK_ERROR_GENERATE_TOKEN_CODE = "KCE_TOKEN_001";
    public static final String KEYCLOAK_ERROR_GENERATE_TOKEN_INFO = "Failed to generate KeyCloak Token.";
    public static final String KEYCLOAK_ERROR_GENERATE_TOKEN_DESC = "Got '%s' from KeyCloak when calling %s";

    // USER 10x
    public static final String KEYCLOAK_ERROR_INQUIRE_USER_CODE = "KCE_USER_101";
    public static final String KEYCLOAK_ERROR_INQUIRE_USER_INFO = "Failed to inquire KeyCloak user.";
    public static final String KEYCLOAK_ERROR_INQUIRE_USER_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_CREATE_USERINFO_CODE = "KCE_USER_102";
    public static final String KEYCLOAK_ERROR_CREATE_USERINFO_INFO = "Failed to create KeyCloak user.";
    public static final String KEYCLOAK_ERROR_CREATE_USERINFO_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_RESET_PASSWORD_CODE = "KCE_USER_103";
    public static final String KEYCLOAK_ERROR_RESET_PASSWORD_INFO = "Failed to reset password of KeyCloak user.";
    public static final String KEYCLOAK_ERROR_RESET_PASSWORD_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_INQUIRE_USERINFO_CODE = "KCE_USER_104";
    public static final String KEYCLOAK_ERROR_INQUIRE_USERINFO_INFO = "Failed to inquire KeyCloak userinfo.";
    public static final String KEYCLOAK_ERROR_INQUIRE_USERINFO_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_UPDATE_USERINFO_CODE = "KCE_USER_105";
    public static final String KEYCLOAK_ERROR_UPDATE_USERINFO_INFO = "Failed to update KeyCloak userinfo.";
    public static final String KEYCLOAK_ERROR_UPDATE_USERINFO_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_DELETE_USERINFO_CODE = "KCE_USER_106";
    public static final String KEYCLOAK_ERROR_DELETE_USERINFO_INFO = "Failed to delete KeyCloak user.";
    public static final String KEYCLOAK_ERROR_DELETE_USERINFO_DESC = "Got '%s' from KeyCloak when calling %s";

    // SESSION 3xx
    public static final String KEYCLOAK_ERROR_INQUIRE_USER_SESSION_CODE = "KCE_SESSION_301";
    public static final String KEYCLOAK_ERROR_INQUIRE_USER_SESSION_INFO = "Failed to inquire sessions of KeyCloak user.";
    public static final String KEYCLOAK_ERROR_INQUIRE_USER_SESSION_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_LOGOUT_USER_SESSION_CODE = "KCE_SESSION_302";
    public static final String KEYCLOAK_ERROR_LOGOUT_USER_SESSION_INFO = "Failed to revoke access a session of KeyCloak user.";
    public static final String KEYCLOAK_ERROR_LOGOUT_USER_SESSION_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_LOGOUT_USER_CODE = "KCE_SESSION_303";
    public static final String KEYCLOAK_ERROR_LOGOUT_USER_INFO = "Failed to revoke access all sessions of KeyCloak user.";
    public static final String KEYCLOAK_ERROR_LOGOUT_USER_DESC = "Got '%s' from KeyCloak when calling %s";

    // ROLE 4xx -- Realm level 41x
    public static final String KEYCLOAK_ERROR_INQUIRE_USER_ROLE_CODE = "KCE_ROLE_401";
    public static final String KEYCLOAK_ERROR_INQUIRE_USER_ROLE_INFO = "Failed to inquire roles of KeyCloak user.";
    public static final String KEYCLOAK_ERROR_INQUIRE_USER_ROLE_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_UPDATE_USER_ROLE_CODE = "KCE_ROLE_402";
    public static final String KEYCLOAK_ERROR_UPDATE_USER_ROLE_INFO = "Failed to update roles of KeyCloak user.";
    public static final String KEYCLOAK_ERROR_UPDATE_USER_ROLE_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_REMOVE_USER_ROLE_CODE = "KCE_ROLE_403";
    public static final String KEYCLOAK_ERROR_REMOVE_USER_ROLE_INFO = "Failed to remove roles of KeyCloak user.";
    public static final String KEYCLOAK_ERROR_REMOVE_USER_ROLE_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String KEYCLOAK_ERROR_INQUIRE_ROLE_CODE = "KCE_ROLE_411";
    public static final String KEYCLOAK_ERROR_INQUIRE_ROLE_INFO = "Failed to inquire KeyCloak realm role.";
    public static final String KEYCLOAK_ERROR_INQUIRE_ROLE_DESC = "Got '%s' from KeyCloak when calling %s";

    public static final String REVOKE_TOKEN_ERROR_CODE = "INVALID_TOKEN";
    public static final String REVOKE_TOKEN_ERROR_INFO = "Unable to close a session.";
    public static final String REVOKE_TOKEN_ERROR_DESC = "Access Token is invalid or Sessions are no longer available.";

    public static final String LDAP_COMMON_ERROR_DESC = "Failed to authenticate LDAP username and password.";
    public static final String MODE_AUTHORIZE_REJECTED = "The 'authorize' mode does not allow on this service.";
    public static final String CONCURRENT_USER_LOGIN = "This user already login with this '%s' session.";

    public static final String USER_SERVICE_BAD_REQUEST_ERROR_CODE = "UNEXPECTED_ERROR";
    public static final String USER_SERVICE_BAD_REQUEST_ERROR_INFO = "Unexpected error occurs before reaching the user service.";
    public static final String USER_SERVICE_BAD_REQUEST_ERROR_DESC = "Error occurs while communicate with %s's user service.";


}
