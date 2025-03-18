package com.test.lsy.jwtreview2.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.lsy.jwtreview2.auth.PrincipalDetails;
import com.test.lsy.jwtreview2.jwt.JwtProperties;
import com.test.lsy.jwtreview2.model.User;
import com.test.lsy.jwtreview2.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        log.info("로그인 요청왔음~~");

        try {
            User requestUser = objectMapper.readValue(request.getInputStream(), User.class);
            log.info("requestUser :: {}", requestUser);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(requestUser.getUsername(), requestUser.getPassword());

            Authentication authenticated = authenticationManager.authenticate(authenticationToken);
            return authenticated;

        } catch(IOException e) {
            log.error("로그인 처리 중 오류 발생", e);
            throw new BadCredentialsException("로그인 실패: 잘못된 자격 증명", e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        log.info("인증되었음~");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        response.addHeader("Authorization", JwtProperties.TOKEN_PREFIX + JwtUtil.createToken(principalDetails));
    }
}
