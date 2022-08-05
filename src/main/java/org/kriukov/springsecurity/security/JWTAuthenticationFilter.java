package org.kriukov.springsecurity.security;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.kriukov.springsecurity.model.UserDto;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static org.kriukov.springsecurity.security.SecurityConstants.*;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private UserDetailsServiceImpl userDetailsService;



    private final AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;

        setFilterProcessesUrl(SIGN_IN_URL);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try{
            var creds = new ObjectMapper().readValue(req.getInputStream(), UserDto.class);
            Collection<? extends GrantedAuthority> authorities = userDetailsService.loadUserByUsername(creds.getUsername()).getAuthorities();
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(creds.getUsername(), creds.getPassword(), authorities));
        }catch (Exception e){
            if(e instanceof BadCredentialsException){
                throw new RuntimeException("error");
            }else{
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth)
            throws IOException, ServletException {


        var token = JWT.create()
                .withSubject(((User) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(SECRET.getBytes()));

        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
        res.setContentType("application/json");
    }
}
