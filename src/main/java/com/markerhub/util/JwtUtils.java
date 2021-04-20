package com.markerhub.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * jwt工具类
 */
@Slf4j
@Data
@Component
@ConfigurationProperties(prefix = "markerhub.jwt")
public class JwtUtils {

    private String secret;
    private long expire;
    private String header;

    /**
     * 生成jwt token
     */
    public String generateToken(long userId) {
        Date nowDate = new Date();
        //过期时间
        Date expireDate = new Date(nowDate.getTime() + expire * 1000);

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject(userId+"")// 代表这个JWT的主体，即它的所有人
                .setIssuedAt(nowDate)// 是一个时间戳，代表这个JWT的签发时间
                .setExpiration(expireDate)//过期时间
                .signWith(SignatureAlgorithm.HS512, secret)//签名 SignatureAlgorithm.HS512:加密方法
                .compact();
    }

    public Claims getClaimByToken(String token) {
        try {
            return Jwts.parser() //得到DefaultJwtParser
                    .setSigningKey(secret) //设置签名的秘钥
                    .parseClaimsJws(token).getBody(); //设置需要解析的jwt
        }catch (Exception e){
            log.debug("validate is token error ", e);
            return null;
        }
    }

    /**
     * token是否过期
     * @return  true：过期
     */
    public boolean isTokenExpired(Date expiration) {
        return expiration.before(new Date());//判断当前日期是否在过期日期之前
    }
}
