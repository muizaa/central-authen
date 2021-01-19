package th.co.ktb.spig.authentication.exception;

import com.ibm.th.microservice.framework.exceptionhandler.model.CustomHttpCodeException;
import org.springframework.http.HttpStatus;

public class UnauthorizedException extends CustomHttpCodeException {

    public UnauthorizedException(String code, String message, String desc) {
        super(HttpStatus.UNAUTHORIZED.value(), code, message, desc);
    }

    public UnauthorizedException(String code, String message, String desc, String originalErrorCode, String originalErrorDesc) {
        super(HttpStatus.UNAUTHORIZED.value(), code, message, desc, originalErrorCode, originalErrorDesc);
    }

}


