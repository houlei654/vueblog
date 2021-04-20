package com.markerhub.controller;

import cn.hutool.core.map.MapUtil;
import cn.hutool.crypto.SecureUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.markerhub.common.dto.LoginDto;
import com.markerhub.common.lang.Result;
import com.markerhub.entity.User;
import com.markerhub.service.UserService;
import com.markerhub.util.JwtUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

//@RequiresAuthentication
//　　验证用户是否登录，等同于方法subject.isAuthenticated() 结果为true时。
//
//@RequiresUser
//　　验证用户是否被记忆，user有两种含义：
//        　　一种是成功登录的（subject.isAuthenticated() 结果为true）；
//        　　另外一种是被记忆的（subject.isRemembered()结果为true）。
//
//@RequiresGuest
//　　验证是否是一个guest的请求，与@RequiresUser完全相反。
//       　　换言之，RequiresUser  == !RequiresGuest。
//       　　此时subject.getPrincipal() 结果为null.
//
//@RequiresRoles
//　　例如：@RequiresRoles("aRoleName");
// 　　void someMethod();
//         　　如果subject中有aRoleName角色才可以访问方法someMethod。如果没有这个权限则会抛出异常AuthorizationException。

@RestController
public class AccountController {

    @Autowired
    UserService userService;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/login")
    public Result login(@Validated @RequestBody LoginDto loginDto, HttpServletResponse response) {

        User user = userService.getOne(new QueryWrapper<User>().eq("username", loginDto.getUsername()));
        Assert.notNull(user, "用户不存在");

        if(!user.getPassword().equals(SecureUtil.md5(loginDto.getPassword()))){
            return Result.fail("密码不正确");
        }
        String jwt = jwtUtils.generateToken(user.getId());

        response.setHeader("Authorization", jwt);
        response.setHeader("Access-control-Expose-Headers", "Authorization");

        return Result.succ(MapUtil.builder()
                .put("id", user.getId())
                .put("username", user.getUsername())
                .put("avatar", user.getAvatar())
                .put("email", user.getEmail())
                .map()
        );
    }

    @RequiresAuthentication
    @GetMapping("/logout")
    public Result logout() {
        SecurityUtils.getSubject().logout();
        return Result.succ(null);
    }

}
