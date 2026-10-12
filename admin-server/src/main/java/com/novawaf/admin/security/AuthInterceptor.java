package com.novawaf.admin.security;

import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.common.Result;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
@RequiredArgsConstructor
public class AuthInterceptor implements HandlerInterceptor {
    private final SessionService sessionService;
    private final ObjectMapper om = new ObjectMapper();

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse resp, Object handler) throws Exception {
        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) return true;
        try {
            LoginUser u = sessionService.resolve(req);
            UserContext.set(u);
            return true;
        } catch (BusinessException e) {
            resp.setStatus(200);
            resp.setContentType("application/json;charset=UTF-8");
            resp.getWriter().write(om.writeValueAsString(Result.fail(e.getCode(), e.getMessage())));
            return false;
        }
    }

    @Override
    public void afterCompletion(HttpServletRequest req, HttpServletResponse resp, Object handler, Exception ex) {
        UserContext.clear();
    }
}
