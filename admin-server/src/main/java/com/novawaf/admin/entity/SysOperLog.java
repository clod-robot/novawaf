package com.novawaf.admin.entity;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class SysOperLog {
    private Long id;
    private String username;
    private String module;
    private String operation;
    private String method;
    private String ip;
    private Integer status;
    private String errorMsg;
    private Integer costMs;
    private LocalDateTime createTime;
}
