package com.novawaf.admin.common;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BusinessException.class)
    public Result<Void> biz(BusinessException e) {
        return Result.fail(e.getCode(), e.getMessage());
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, BindException.class})
    public Result<Void> valid(Exception e) {
        return Result.fail(400, "参数校验失败");
    }

    @ExceptionHandler(Exception.class)
    public Result<Void> all(Exception e, HttpServletRequest req) {
        log.error("Unhandled error on {} : {}", req.getRequestURI(), e.toString());
        return Result.fail(500, "服务器内部错误");
    }
}
