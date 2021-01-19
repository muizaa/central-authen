# central-authentication

### Error List
- HTTP Status 401
    - NOT_AUTHORIZED (Error from LDAP)
    - USER_LOCKED (User locked from LDAP)
    - CONCURRENT_LOGIN (This user already has remaining session)
    - REJECTED (This mode is not support on this service, currently for 'authorize' mode)
    - XXX (The error code from User-Service, can be used for customize case e.g. this user is not allow for this service)
    - UNEXPECTED_ERROR (Error happen between Kong and User-Service)
    
 - HTTP Status 422
    - KCE_XXX_NNN (Error from Keycloak)
    - INVALID_TOKEN (Cannot revoke access token)
    
- HTTP Status 503
    - AD_UNAVAILABLE (Cannot connect ot AD)
    - F999 (General Error from framework - unexpected exception)
    
 ### Audit Event Type
 ----
 - LOGIN # Normal Login
 - LOGIN_ERROR # Failed to login
 ----
 - LOGOUT # Normal Logout
 - LOGOUT_ERROR # Failed to logout
 ----
 - REFRESH_TOKEN # Request refresh token
 - REFRESH_TOKEN_ERROR # Failed to request refresh token
 ----
 - AUTHORIZE_MODE # Login with authorize mode
 - AUTHORIZE_MODE_ERROR # Failed to login with authorize mode
 ----
 - LOGIN_VIA_CLIENT_ID # Login with client id (for external service e.g. documentum)
 - LOGIN_VIA_CLIENT_ID_ERROR # Failed to login with client id
 ----
 - EXCHANGE_TOKEN # Exchange Token
 - EXCHANGE_TOKEN_ERROR # Failed to exchange token
 ----
 - SESSION_CLEARED # Kick session id (when concurrent login)
 ----