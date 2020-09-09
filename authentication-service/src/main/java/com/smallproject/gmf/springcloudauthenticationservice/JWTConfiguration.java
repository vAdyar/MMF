package com.smallproject.gmf.springcloudauthenticationservice;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import static java.util.Collections.emptyList;

//@Configuration
public class JWTConfiguration {
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
//
//
//@Entity(name = "user")
//class ApplicationUser {
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private long id;
//    private String username;
//    private String password;
//
//    public long getId() {
//        return id;
//    }
//
//    public String getUsername() {
//        return username;
//    }
//
//    public void setUsername(String username) {
//        this.username = username;
//    }
//
//    public String getPassword() {
//        return password;
//    }
//
//    public void setPassword(String password) {
//        this.password = password;
//    }
//}
//
//interface ApplicationUserRepository extends JpaRepository<ApplicationUser, Long> {
//    ApplicationUser findByUsername(String username);
//}
//
//
//@RestController
//@RequestMapping("/users")
//class UserController {
//
//    private ApplicationUserRepository applicationUserRepository;
//    @Autowired
//    private BCryptPasswordEncoder bCryptPasswordEncoder;
//
//    public UserController(ApplicationUserRepository applicationUserRepository,
//                          BCryptPasswordEncoder bCryptPasswordEncoder) {
//        this.applicationUserRepository = applicationUserRepository;
//        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
//    }
//
//    @PostMapping("/sign-up")
//    public void signUp(@RequestBody ApplicationUser user) {
//        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
//        applicationUserRepository.save(user);
//    }
//
//    @GetMapping("")
//    public String message() {
//        return "Hello World!";
//    }
//}
//
//@Service
//class UserDetailsServiceImpl implements UserDetailsService {
//    private ApplicationUserRepository applicationUserRepository;
//
//    public UserDetailsServiceImpl(ApplicationUserRepository applicationUserRepository) {
//        this.applicationUserRepository = applicationUserRepository;
//    }
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        ApplicationUser applicationUser = applicationUserRepository.findByUsername(username);
//        if (applicationUser == null) {
//            throw new UsernameNotFoundException(username);
//        }
//        return new User(applicationUser.getUsername(), applicationUser.getPassword(), emptyList());
//    }
//}
//
//class SecurityConstants {
//    public static final String SECRET = "SecretKeyToGenJWTs";
//    public static final long EXPIRATION_TIME = 864_000_000; // 10 days
//    public static final String TOKEN_PREFIX = "Bearer ";
//    public static final String HEADER_STRING = "Authorization";
//    public static final String SIGN_UP_URL = "/users/sign-up";
//}
//
//class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
//    private AuthenticationManager authenticationManager;
//
//    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
//        this.authenticationManager = authenticationManager;
//    }
//
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest req,
//                                                HttpServletResponse res) {
//        try {
//            ApplicationUser creds = new ObjectMapper()
//                    .readValue(req.getInputStream(), ApplicationUser.class);
//
//            return authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(
//                            creds.getUsername(),
//                            creds.getPassword(),
//                            new ArrayList<>())
//            );
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    @Override
//    protected void successfulAuthentication(HttpServletRequest req,
//                                            HttpServletResponse res,
//                                            FilterChain chain,
//                                            Authentication auth) throws IOException, ServletException {
//
//        String token = JWT.create()
//                .withSubject(((User) auth.getPrincipal()).getUsername())
//                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
//                .sign(Algorithm.HMAC512(SecurityConstants.SECRET.getBytes()));
//        System.out.println("Token: "+token);
//        res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);
//    }
//}
//
//@EnableWebSecurity
//class WebSecurity extends WebSecurityConfigurerAdapter {
//    private UserDetailsServiceImpl userDetailsService;
//    private BCryptPasswordEncoder bCryptPasswordEncoder;
//
//    public WebSecurity(UserDetailsServiceImpl userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
//        this.userDetailsService = userDetailsService;
//        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.cors().and().csrf().disable().authorizeRequests()
//                .antMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL).permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
//                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
//                // this disables session creation on Spring Security
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//    }
//
//    @Override
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
//    }
//
//    @Bean
//    CorsConfigurationSource corsConfigurationSource() {
//        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
//        return source;
//    }
//}
//
//
//class JWTAuthorizationFilter extends BasicAuthenticationFilter {
//
//    public JWTAuthorizationFilter(AuthenticationManager authManager) {
//        super(authManager);
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest req,
//                                    HttpServletResponse res,
//                                    FilterChain chain) throws IOException, ServletException {
//        String header = req.getHeader(SecurityConstants.HEADER_STRING);
//
//        if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
//            chain.doFilter(req, res);
//            return;
//        }
//
//        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//        chain.doFilter(req, res);
//    }
//
//    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
//        String token = request.getHeader(SecurityConstants.HEADER_STRING);
//        if (token != null) {
//            // parse the token.
//            String user = JWT.require(Algorithm.HMAC512(SecurityConstants.SECRET.getBytes()))
//                    .build()
//                    .verify(token.replace(SecurityConstants.TOKEN_PREFIX, ""))
//                    .getSubject();
//
//            if (user != null) {
//                return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
//            }
//            return null;
//        }
//        return null;
//    }
//}
