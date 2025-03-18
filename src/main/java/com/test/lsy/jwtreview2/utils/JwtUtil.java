package com.test.lsy.jwtreview2.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.test.lsy.jwtreview2.auth.PrincipalDetails;
import com.test.lsy.jwtreview2.jwt.JwtProperties;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;

@Slf4j
public class JwtUtil {

    public static String createToken(PrincipalDetails principalDetails) {

//        Date expiration = new Date(System.currentTimeMillis() + 1000 * 60 * 60);
        Date expiration = new Date(System.currentTimeMillis() + 1000 * 60 * 1);  // 1분 후


        log.info("Token expiration: {}", expiration);

        return JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(expiration)
                .withClaim("id", principalDetails.getUser().getId()) // 사용자 ID
                .withClaim("username", principalDetails.getUser().getUsername()) // 사용자 이름
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); // 암호화 키
    }
}
