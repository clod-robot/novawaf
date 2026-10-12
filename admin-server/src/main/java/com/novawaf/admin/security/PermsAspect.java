package com.novawaf.admin.security;

import com.novawaf.admin.common.BusinessException;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class PermsAspect {

    @Around("@annotation(requirePerms)")
    public Object check(ProceedingJoinPoint pjp, RequirePerms requirePerms) throws Throwable {
        LoginUser u = UserContext.get();
        if (u == null) throw new BusinessException(401, "未登录");
        if (!u.isAdmin() && (u.getPerms() == null || !u.getPerms().contains(requirePerms.value()))) {
            throw new BusinessException(403, "无权限: " + requirePerms.value());
        }
        return pjp.proceed();
    }
}
