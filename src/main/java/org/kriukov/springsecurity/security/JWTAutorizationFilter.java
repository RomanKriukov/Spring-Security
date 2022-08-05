package org.kriukov.springsecurity.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import static org.kriukov.springsecurity.security.SecurityConstants.*;

public class JWTAutorizationFilter extends BasicAuthenticationFilter {

    private UserDetailsServiceImpl userDetailsService;
    public JWTAutorizationFilter(AuthenticationManager authManager,
                                 UserDetailsServiceImpl userDetailsService){
        super(authManager);
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        var header = req.getHeader(HEADER_STRING);

        if(header == null || !header.startsWith(TOKEN_PREFIX)){
            chain.doFilter(req, res);
            return;
        }

        var authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request){
        var token = request.getHeader(HEADER_STRING);
        if(token != null){
            // parse the token
            String user = JWT.require(Algorithm.HMAC512(SECRET.getBytes()))
                    .build()
                    .verify(token.replace(TOKEN_PREFIX, ""))
                    .getSubject();

            if(user != null){
                Collection<? extends GrantedAuthority> authorities = userDetailsService.loadUserByUsername(user).getAuthorities();
                return new UsernamePasswordAuthenticationToken(user, null, authorities);
            }
            return null;
        }
        return null;
    }
}
