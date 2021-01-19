package th.co.ktb.spig.authentication.util;

import com.ibm.th.microservice.framework.exceptionhandler.model.*;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.ConversionNotSupportedException;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.validation.BindException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolationException;
import java.util.Arrays;

public class RequestUtil {

    private RequestUtil() {
        throw new AssertionError();
    }

    private static final String[] IP_HEADER_CANDIDATES = {
            "X-Forwarded-For",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "REMOTE_ADDR"
    };


    public static String getIPAddress(RequestAttributes requestAttributes) {

        if (requestAttributes == null) {
            return "0.0.0.0";
        }

        HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
        String ipFromHeader = Arrays.stream(IP_HEADER_CANDIDATES)
                .map(request::getHeader)
                .filter(h -> h != null && h.length() != 0 && !"unknown".equalsIgnoreCase(h))
                .map(h -> h.split(",")[0])
                .reduce("", (h1, h2) -> h1 + ":" + h2);
        if(ipFromHeader.startsWith(":")) {
            ipFromHeader = ipFromHeader.substring(1);
        }

        String requestRemoteAddr = request.getRemoteAddr();
        if (StringUtils.equals(requestRemoteAddr, "0:0:0:0:0:0:0:1")) requestRemoteAddr = "127.0.0.1";

        if (StringUtils.isEmpty(ipFromHeader)) {
            return requestRemoteAddr;
        } else {
            return ipFromHeader;
        }

    }

    // This method copy from MVC SPIG framework version 1.0.2
    public static HttpStatus getStatusFromException(Exception ex) {
        HttpStatus status;
        if (ex instanceof HttpRequestMethodNotSupportedException) {
            status = HttpStatus.METHOD_NOT_ALLOWED;
            return status;
        } else if (ex instanceof HttpMediaTypeNotSupportedException) {
            status = HttpStatus.UNSUPPORTED_MEDIA_TYPE;
            return status;
        } else if (ex instanceof HttpMediaTypeNotAcceptableException) {
            status = HttpStatus.NOT_ACCEPTABLE;
            return status;
        } else if (ex instanceof MissingPathVariableException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof MissingServletRequestParameterException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof ServletRequestBindingException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof ConversionNotSupportedException) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            return status;
        } else if (ex instanceof TypeMismatchException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof HttpMessageNotReadableException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof HttpMessageNotWritableException) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            return status;
        } else if (ex instanceof MethodArgumentNotValidException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof MissingServletRequestPartException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof BindException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof ResourceConflictException) {
            status = HttpStatus.CONFLICT;
            return status;
        } else if (ex instanceof ResourceNotFoundException) {
            status = HttpStatus.NOT_FOUND;
            return status;
        } else if (ex instanceof BusinessProcessingException) {
            status = HttpStatus.UNPROCESSABLE_ENTITY;
            return status;
        } else if (ex instanceof BusinessProcessingTimeoutException) {
            status = HttpStatus.GATEWAY_TIMEOUT;
            return status;
        } else if (ex instanceof NotImplementedException) {
            status = HttpStatus.NOT_IMPLEMENTED;
            return status;
        } else if (ex instanceof ConstraintViolationException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof InputValidationException) {
            status = HttpStatus.BAD_REQUEST;
            return status;
        } else if (ex instanceof NullPointerException) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            return status;
        } else if (ex instanceof CustomHttpCodeException) {
            CustomHttpCodeException chce = (CustomHttpCodeException)ex;
            status = HttpStatus.valueOf(chce.getHttpCode());
            return status;
        } else {
            status = HttpStatus.SERVICE_UNAVAILABLE;
            return status;
        }
    }
}



