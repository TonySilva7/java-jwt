package com.tony.jwtjava.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class MyJWTValidateFilter extends BasicAuthenticationFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_HEADER = "Bearer ";

    public MyJWTValidateFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String attrAuthorization = request.getHeader(AUTHORIZATION_HEADER);

        if (attrAuthorization == null) {
            chain.doFilter(request, response);
            return;
        }

        if (!attrAuthorization.startsWith(BEARER_HEADER)) {
            chain.doFilter(request, response);
            return;
        }

        String token = attrAuthorization.replace(BEARER_HEADER, "");
        UsernamePasswordAuthenticationToken authenticationToken = getAuthenticationToken(token);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);
    }

    // Extrai os dados do token, informados durante a autenticação.
    private UsernamePasswordAuthenticationToken getAuthenticationToken(String token) {
        String userName = JWT.require(Algorithm.HMAC512(MyJWTAuthenticateFilter.TOKEN_PASSWORD))
                .build()
                .verify(token)
                .getSubject();

        if (userName == null) {
            return null;
        }

        return new UsernamePasswordAuthenticationToken(userName, null, new ArrayList<>());
    }
}
