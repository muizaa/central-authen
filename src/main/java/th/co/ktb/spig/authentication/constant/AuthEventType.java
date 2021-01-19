package th.co.ktb.spig.authentication.constant;

public enum AuthEventType {

    LOGIN(),
    LOGIN_ERROR(),

    AUTHORIZE_MODE(),
    AUTHORIZE_MODE_ERROR(),

    LOGIN_VIA_CLIENT_ID(),
    LOGIN_VIA_CLIENT_ID_ERROR(),

    LOGOUT(),
    LOGOUT_ERROR(),

    REFRESH_TOKEN(),
    REFRESH_TOKEN_ERROR(),

    EXCHANGE_TOKEN(),
    EXCHANGE_TOKEN_ERROR(),

    SESSION_CLEARED();

}
