package com.novawaf.admin.common;

import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {
    private final int code;
    public BusinessException(String msg) { super(msg); this.code = 400; }
    public BusinessException(int code, String msg) { super(msg); this.code = code; }
}
