package th.co.ktb.spig.authentication.constant;

public enum AuthErrorCode {

    // 401
    NOT_AUTHORIZED("Incorrect username or password."),
    USER_LOCKED( "User locker due to exceed login limit."),

    CONCURRENT_LOGIN( "User already logged in."),
    REJECTED( "This service does not support this mode."),

    // 503
    AD_UNAVAILABLE("Cannot connect AD"),
    USER_SERVICE_UNAVAILABLE("Cannot connect user-service");

    private String message;

    AuthErrorCode(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
