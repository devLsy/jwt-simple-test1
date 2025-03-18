package com.test.lsy.jwtreview2.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.test.lsy.jwtreview2.auth.PrincipalDetails;
import com.test.lsy.jwtreview2.jwt.JwtProperties;
import com.test.lsy.jwtreview2.model.User;
import com.test.lsy.jwtreview2.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

// 토큰 검증
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final UserRepository repository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        log.info("JWT 토큰 인증 요청~~~");

        String header = request.getHeader(JwtProperties.HEADER_STRING);
        log.info("header :: {}", header);

        String requestURI = request.getRequestURI();
        if (requestURI.equals("/login") || requestURI.equals("/join")) {  // 로그인, 회원가입 경로 예시
            filterChain.doFilter(request, response);  // 로그인 요청은 JWT 검증을 건너뜁니다.
            return;
        }

        if(header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            sendErrorResponse(response, "헤더가 없거나 올바르지 않습니다.");
            return;
        }

        try {
            String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace("Bearer ", "");
            log.info("jwtToken :: {}", jwtToken);

            String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build()
                    .verify(jwtToken)
                    .getClaim("username")
                    .asString();

            log.info("username :: {}", username);

            if(username != null) {
                repository.findByUsername(username)
                        .map(user -> new PrincipalDetails(user))
                        .ifPresent(principalDetails -> {
                            log.info("principalDetails :: {}", principalDetails.getUsername());
                            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        });

//                Optional<User> findUser = repository.findByUsername(username);
//                PrincipalDetails principalDetails = new PrincipalDetails(findUser.get());
//
//                log.info("principalDetails :: {}", principalDetails.getUsername());
//
//                Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
//                log.info("authentication :: {}", authentication);
//                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request, response);

        } catch (TokenExpiredException e) {
            sendErrorResponse(response, "토큰이 만료되었습니다!!!!");
        } catch (JWTVerificationException e) {
            sendErrorResponse(response, "유효하지 않은 토큰입니다!!!!!");
        } catch (Exception e) {
            sendErrorResponse(response, "토큰 검증 중 오류가 발생했습니다!!!!");
        }
    }

    private void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
    }
}
