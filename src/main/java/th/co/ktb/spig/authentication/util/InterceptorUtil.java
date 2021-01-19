package th.co.ktb.spig.authentication.util;

import com.ibm.th.microservice.framework.core.model.processingstat.ProcessingStat;

import javax.servlet.http.HttpServletRequest;

public class InterceptorUtil {

    public static final void reviseProcessingStat(HttpServletRequest request, String service){
        ProcessingStat stat = (ProcessingStat)request.getAttribute("com.ibm.th.microservice.framework.processingStat");
        stat.setHttpRequestUri(stat.getHttpRequestUri().replace("central",service));
        request.setAttribute("com.ibm.th.microservice.framework.processingStat", stat);
    }
}
