package th.co.ktb.spig.authentication.exception;

import com.ibm.th.microservice.framework.exceptionhandler.model.CustomHttpCodeException;
import org.springframework.http.HttpStatus;

public class ServiceUnavailableException extends CustomHttpCodeException {

    public ServiceUnavailableException(String code, String message, String desc) {
        super(HttpStatus.SERVICE_UNAVAILABLE.value(), code, message, desc);
    }

    public ServiceUnavailableException(String code, String message, String desc, String originalErrorCode, String originalErrorDesc) {
        super(HttpStatus.SERVICE_UNAVAILABLE.value(), code, message, desc, originalErrorCode, originalErrorDesc);
    }

}


