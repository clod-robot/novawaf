package com.novawaf.admin.common;

import lombok.Data;
import java.io.Serializable;

@Data
public class Result<T> implements Serializable {
    private int code;
    private String msg;
    private T data;

    public static <T> Result<T> ok() { return ok(null); }
    public static <T> Result<T> ok(T data) {
        Result<T> r = new Result<>(); r.code = 200; r.msg = "success"; r.data = data; return r;
    }
    public static <T> Result<T> fail(int code, String msg) {
        Result<T> r = new Result<>(); r.code = code; r.msg = msg; return r;
    }
    public static <T> Result<T> fail(String msg) { return fail(500, msg); }
}
