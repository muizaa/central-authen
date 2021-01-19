package th.co.ktb.spig.authentication.repository.entity;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class AuditLog {

    private Long id;
    private String realm;
    private String uuid;
    private String ipAddress;
    private String employeeId;
    private String branchCode;
    private String rankCode;
    private String roles;
    private String eventType;
    private Integer status;
    private String errorCode;
    private String errorMessage;
    private LocalDateTime requestTimestamp;
    private LocalDateTime responseTimestamp;
    private String sessionId;
    private String clearedSessionIds;

}
