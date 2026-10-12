package com.novawaf.admin.service;

import com.novawaf.admin.entity.SysOperLog;
import com.novawaf.admin.mapper.SysOperLogMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {
    private final SysOperLogMapper operLogMapper;

    /** 异步写审计日志, 失败不影响主流程 */
    @Async("bizExecutor")
    public void record(String username, String module, String operation, String method,
                       String ip, int status, String errorMsg, int costMs) {
        try {
            SysOperLog o = new SysOperLog();
            o.setUsername(username); o.setModule(module); o.setOperation(truncate(operation, 255));
            o.setMethod(method); o.setIp(ip); o.setStatus(status);
            o.setErrorMsg(truncate(errorMsg, 1000)); o.setCostMs(costMs);
            operLogMapper.insert(o);
        } catch (Exception e) {
            log.warn("audit write failed: {}", e.toString());
        }
    }

    private String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() > max ? s.substring(0, max) : s;
    }
}
