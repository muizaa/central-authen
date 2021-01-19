package th.co.ktb.spig.authentication.controller;

import com.fasterxml.jackson.annotation.JsonIgnore;
import springfox.documentation.annotations.ApiIgnore;
import th.co.ktb.spig.authentication.entity.*;
import th.co.ktb.spig.authentication.impl.CentralAuthenticationImpl;
import com.ibm.th.microservice.framework.exceptionhandler.model.ErrorsList;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.ResponseHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import springfox.documentation.swagger2.annotations.EnableSwagger2;
import th.co.ktb.spig.authentication.util.InterceptorUtil;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@EnableSwagger2
@RestController
@EnableAutoConfiguration
@Api(tags = "Central-Authentication",
        value = "/ktb/rest/central")
@RequestMapping(value = "/v1/authentication")
@CrossOrigin(methods = {RequestMethod.POST}, origins = "*")
public class CentralAuthenticationController {

    private final Logger log = LoggerFactory.getLogger(CentralAuthenticationController.class);

    @Autowired
    private CentralAuthenticationImpl centralAuthentication;

    // POST: /ktb/rest/central/v1/authentication/generateTokens
    @ApiOperation(value = "Authentication to generate tokens", notes = "This API is used for generating access token and refresh token via ldap.")
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Success", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.")}),
            @ApiResponse(code = 400, message = "Bad Request", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Forbidden"),
            @ApiResponse(code = 404, message = "Not Found"),
            @ApiResponse(code = 422, message = "Unprocessable Entity (Business Error)", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 500, message = "Internal server error occurred", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 502, message = "Bad Gateway", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 503, message = "Service Unavailable", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 504, message = "Gateway Timeout", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class)
    })
    @RequestMapping(value = "/generateToken", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public
    @ResponseBody
    AuthenticationTokenResponse authenticationUserToken(
            @ApiParam(name = "ldapInfoRequest", value = "LDAP Information Request", required = true)
            @Valid @RequestBody(required = true) LDAPInfoRequest ldapInfoRequest,
            HttpServletRequest request) throws Exception {

        log.info(request.getMethod() + " " + request.getRequestURI() + " INITIATED...");
        InterceptorUtil.reviseProcessingStat(request, ldapInfoRequest.getService());
        return centralAuthentication.authenticationUserToken(ldapInfoRequest);
    }

    // POST: /ktb/rest/central/v1/authentication/refreshToken
    @ApiOperation(value = "Authentication to generate tokens from refresh token", notes = "This API is used for generating access token and refresh token from refresh token.")
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Success", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.")}),
            @ApiResponse(code = 400, message = "Bad Request", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Forbidden"),
            @ApiResponse(code = 404, message = "Not Found"),
            @ApiResponse(code = 422, message = "Unprocessable Entity (Business Error)", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 500, message = "Internal server error occurred", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 502, message = "Bad Gateway", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 503, message = "Service Unavailable", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 504, message = "Gateway Timeout", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class)
    })
    @RequestMapping(value = "/refreshToken", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public
    @ResponseBody
    AuthenticationTokenResponse authenticationRefreshToken(
            @ApiParam(name = "refreshTokenRequest", value = "Refresh Token Request", required = true)
            @Valid @RequestBody(required = true) RefreshTokenRequest refreshTokenRequest,
            HttpServletRequest request) throws Exception {

        log.info(request.getMethod() + " " + request.getRequestURI() + " INITIATED...");
        InterceptorUtil.reviseProcessingStat(request, refreshTokenRequest.getService());
        return centralAuthentication.authenticationRefreshToken(refreshTokenRequest);
    }

    // POST: /ktb/rest/central/v1/authentication/generateServiceAccountsToken
    @ApiOperation(value = "Authentication to generate tokens by service", notes = "This API is used for generating access token and refresh token via service accounts.")
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Success", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.")}),
            @ApiResponse(code = 400, message = "Bad Request", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Forbidden"),
            @ApiResponse(code = 404, message = "Not Found"),
            @ApiResponse(code = 422, message = "Unprocessable Entity (Business Error)", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 500, message = "Internal server error occurred", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 502, message = "Bad Gateway", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 503, message = "Service Unavailable", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 504, message = "Gateway Timeout", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class)
    })
    @RequestMapping(value = "/generateServiceAccountsToken", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public
    @ResponseBody
    AuthenticationTokenResponse authenticationClientId(
            @ApiParam(name = "serviceAccountsRequest", value = "Service Accounts Request", required = true)
            @Valid @RequestBody(required = true) ServiceAccountsRequest serviceAccountsRequest,
            HttpServletRequest request) throws Exception {

        log.info(request.getMethod() + " " + request.getRequestURI() + " INITIATED...");
        InterceptorUtil.reviseProcessingStat(request, serviceAccountsRequest.getService());
        return centralAuthentication.authenticationClientId(serviceAccountsRequest);
    }

    // POST: /ktb/rest/central/v1/authentication/revokeToken
    @ApiOperation(value = "Authentication to revoke tokens from access token", notes = "This API is used for revoking access token and refresh token from access token. Only session in token will be revoked.")
    @ApiResponses(value = {@ApiResponse(code = 204, message = "No Content", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.")}),
            @ApiResponse(code = 400, message = "Bad Request", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Forbidden"),
            @ApiResponse(code = 404, message = "Not Found"),
            @ApiResponse(code = 422, message = "Unprocessable Entity (Business Error)", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 500, message = "Internal server error occurred", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 502, message = "Bad Gateway", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 503, message = "Service Unavailable", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 504, message = "Gateway Timeout", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class)
    })
    @RequestMapping(value = "/revokeToken", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(value = HttpStatus.NO_CONTENT)
    public
    @ResponseBody
    void revokeToken(
            @ApiParam(name = "revokeTokenRequest", value = "Revoke Token Request", required = true)
            @Valid @RequestBody(required = true) RevokeTokenRequest revokeTokenRequest,
            HttpServletRequest request) throws Exception {

        log.info(request.getMethod() + " " + request.getRequestURI() + " INITIATED...");
        InterceptorUtil.reviseProcessingStat(request, revokeTokenRequest.getService());
        centralAuthentication.revokeToken(revokeTokenRequest);
    }

    // POST: /ktb/rest/central/v1/authentication/exchangeToken
    @ApiOperation(value = "Authentication to exchange tokens from refresh token", notes = "This API is used for exchange attributes in the token from refresh token. Only allowance attributes can be exchanged.")
    @ApiResponses(value = {@ApiResponse(code = 204, message = "No Content", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.")}),
            @ApiResponse(code = 400, message = "Bad Request", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Forbidden"),
            @ApiResponse(code = 404, message = "Not Found"),
            @ApiResponse(code = 422, message = "Unprocessable Entity (Business Error)", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 500, message = "Internal server error occurred", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 502, message = "Bad Gateway", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 503, message = "Service Unavailable", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class),
            @ApiResponse(code = 504, message = "Gateway Timeout", responseHeaders = {@ResponseHeader(name = "x-request-id", description = "36 characters unique ID used for traceability purpose. If provided on a request, the same value is echoed back. If not provided on a request, API generates and returns UUID.", response = String.class)}, response = ErrorsList.class)
    })
    @RequestMapping(value = "/exchangeToken", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(value = HttpStatus.OK)
    public
    @ResponseBody
    AuthenticationTokenResponse exchangeToken(
            @ApiParam(name = "exchangeTokenRequest", value = "Exchange Token Request", required = true)
            @Valid @RequestBody(required = true) ExchangeTokenRequest exchangeTokenRequest,
            HttpServletRequest request) throws Exception {

        log.info(request.getMethod() + " " + request.getRequestURI() + " INITIATED...");
        InterceptorUtil.reviseProcessingStat(request, exchangeTokenRequest.getService());
        return centralAuthentication.exchangeToken(exchangeTokenRequest);
    }

    // POST: /ktb/rest/central/v1/authentication/admin/execute
    @ApiIgnore
    @RequestMapping(value = "/admin/execute", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(value = HttpStatus.NO_CONTENT)
    public
    @ResponseBody
    void adminExecute(
            @ApiParam(name = "adminRequest", value = "Admin Request", required = true)
            @Valid @RequestBody(required = true) AdminRequest adminRequest,
            HttpServletRequest request) throws Exception {

        log.info(request.getMethod() + " " + request.getRequestURI() + " INITIATED...");
        InterceptorUtil.reviseProcessingStat(request, adminRequest.getService());
        centralAuthentication.adminExecute(adminRequest);
    }

}


