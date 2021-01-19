package th.co.ktb.spig.authentication.service;

import org.springframework.ldap.CommunicationException;
import th.co.ktb.spig.authentication.constant.AuthErrorCode;
import th.co.ktb.spig.authentication.constant.CommonConstant;
import th.co.ktb.spig.authentication.constant.ErrorMessageConstant;
import th.co.ktb.spig.authentication.exception.ServiceUnavailableException;
import th.co.ktb.spig.authentication.exception.UnauthorizedException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.core.ContextSource;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

public class LdapClient {

    @Value("${ldap.base}")
    private String ldapBase;

    @Value("${ldap.domain}")
    private String ldapDomain;

    @Autowired
    private ContextSource contextSource;

    private final Logger log = LoggerFactory.getLogger(LdapClient.class);

    public void authenticate(final String username, final String password) {
        try {
            // verify username and password
            contextSource.getContext(String.format(CommonConstant.LDAP_USERNAME, username, ldapDomain), password);
        } catch (AuthenticationException e) {

            log.error("Authentication Failed {}", e.getMessage());

            String errorCode = getLDAPErrorCode(e.getMessage());
            String errorDesc = getLDAPErrorDesc(e.getMessage());

            if(CommonConstant.USER_LOCKED.equals(errorCode)){
                throw new UnauthorizedException(AuthErrorCode.USER_LOCKED.name(),
                        AuthErrorCode.USER_LOCKED.getMessage(),
                        ErrorMessageConstant.LDAP_COMMON_ERROR_DESC,
                        errorCode,
                        errorDesc);
            }else {
                // default case
                throw new UnauthorizedException(AuthErrorCode.NOT_AUTHORIZED.name(),
                        AuthErrorCode.NOT_AUTHORIZED.getMessage(),
                        ErrorMessageConstant.LDAP_COMMON_ERROR_DESC,
                        errorCode,
                        errorDesc);
            }
        } catch (CommunicationException e){
            log.error(e.getMessage(), e);
            throw new ServiceUnavailableException(AuthErrorCode.AD_UNAVAILABLE.name(),
                    AuthErrorCode.AD_UNAVAILABLE.getMessage(),
                    e.getMessage());
        }
    }

    private String getLDAPErrorCode(String exceptionMsg) {
        String errorCode = "";
        try {
            StringTokenizer st1 = new StringTokenizer(exceptionMsg, ",");
            st1.nextElement();
            st1.nextElement();
            String dataMsg = (String) st1.nextElement();
            StringTokenizer st2 = new StringTokenizer(dataMsg.trim(), " ");
            st2.nextElement();
            errorCode = (String) st2.nextElement();
        }catch (Exception e){
            errorCode = exceptionMsg;
        }
        return errorCode;
    }
    private String getLDAPErrorDesc(String exceptionMsg) {
        String errorDesc = "";
        try {
            StringTokenizer st1 = new StringTokenizer(exceptionMsg, ";");
            errorDesc = (String) st1.nextElement();
        }catch (Exception e){
            errorDesc = exceptionMsg;
        }
        return errorDesc;
    }

    public JSONObject getUserInformation(String username) {
        JSONObject response = null;
        try {
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String filter = String.format(CommonConstant.LDAP_SAMACCOUNTNAME, username);
            NamingEnumeration values = contextSource.getReadOnlyContext().search(CommonConstant.LDAP_DOMAIN, filter, searchControls);
            if (values.hasMore()) {
                SearchResult result = (SearchResult) values.next();
                NamingEnumeration enumAtrr = result.getAttributes().getAll();
                Map<String, String> attributesMapping = new HashMap<>();
                while (enumAtrr.hasMore()) {
                    Attribute atrr = (Attribute) enumAtrr.next();
                    attributesMapping.put(atrr.getID(), atrr.get().toString());
                }
                response = new JSONObject(attributesMapping);
            }
            // if username is not found, response is null
        } catch (NamingException e) {
            log.error("Username not found {}" , e.getMessage(),e);
            String errorCode = getLDAPErrorCode(e.getMessage());
            String errorDesc = getLDAPErrorDesc(e.getMessage());
            // username not found
            throw new UnauthorizedException(AuthErrorCode.NOT_AUTHORIZED.name(),
                    AuthErrorCode.NOT_AUTHORIZED.getMessage(),
                    ErrorMessageConstant.LDAP_COMMON_ERROR_DESC,
                    errorCode,
                    errorDesc);
        }
        return response;
    }
}