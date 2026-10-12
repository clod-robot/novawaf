package com.novawaf.admin.controller;

import com.novawaf.admin.common.BusinessException;
import com.novawaf.admin.common.Result;
import com.novawaf.admin.entity.SysUser;
import com.novawaf.admin.mapper.SysUserMapper;
import com.novawaf.admin.security.RequirePerms;
import com.novawaf.admin.security.UserContext;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/system/users")
@RequiredArgsConstructor
public class SysUserController {
    private final SysUserMapper userMapper;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @RequirePerms("sys:user:list")
    @GetMapping
    public Result<Map<String, Object>> page(@RequestParam(defaultValue = "1") int page,
                                            @RequestParam(defaultValue = "10") int size,
                                            @RequestParam(required = false) String username) {
        if (size > 100) size = 100;
        List<SysUser> rows = userMapper.selectPage(username, (page - 1) * size, size);
        rows.forEach(u -> u.setPassword(null));       // 绝不返回密码哈希
        Map<String, Object> m = new HashMap<>();
        m.put("total", userMapper.count(username));
        m.put("rows", rows);
        return Result.ok(m);
    }

    @Data
    public static class UserReq {
        private String username;
        private String password;
        private String nickname;
        private String email;
        private String phone;
        private Integer status;
    }

    @RequirePerms("sys:user:list")
    @PostMapping
    public Result<Void> add(@RequestBody UserReq req) {
        if (req.getUsername() == null || req.getUsername().isBlank())
            throw new BusinessException("用户名不能为空");
        if (req.getPassword() == null || req.getPassword().length() < 6)
            throw new BusinessException("密码至少6位");
        if (userMapper.selectByUsername(req.getUsername()) != null)
            throw new BusinessException("用户名已存在");
        SysUser u = new SysUser();
        u.setUsername(req.getUsername());
        u.setPassword(encoder.encode(req.getPassword()));
        u.setNickname(req.getNickname());
        u.setEmail(req.getEmail());
        u.setPhone(req.getPhone());
        u.setStatus(req.getStatus() == null ? 1 : req.getStatus());
        userMapper.insert(u);
        return Result.ok();
    }

    @RequirePerms("sys:user:list")
    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody UserReq req) {
        SysUser u = userMapper.selectById(id);
        if (u == null) throw new BusinessException("用户不存在");
        u.setNickname(req.getNickname());
        u.setEmail(req.getEmail());
        u.setPhone(req.getPhone());
        if (req.getStatus() != null) u.setStatus(req.getStatus());
        userMapper.update(u);
        return Result.ok();
    }

    @RequirePerms("sys:user:list")
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        if (UserContext.get().getUserId().equals(id))
            throw new BusinessException("不能删除当前登录用户");
        if (id == 1L) throw new BusinessException("不能删除内置管理员");
        userMapper.deleteById(id);
        return Result.ok();
    }

    @Data
    public static class PwdReq { private String password; }

    @RequirePerms("sys:user:list")
    @PostMapping("/{id}/password")
    public Result<Void> resetPwd(@PathVariable Long id, @RequestBody PwdReq req) {
        if (req.getPassword() == null || req.getPassword().length() < 6)
            throw new BusinessException("密码至少6位");
        userMapper.updatePassword(id, encoder.encode(req.getPassword()));
        return Result.ok();
    }
}
