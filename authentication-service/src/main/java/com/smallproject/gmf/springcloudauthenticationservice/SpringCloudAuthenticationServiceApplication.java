package com.smallproject.gmf.springcloudauthenticationservice;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.validation.Valid;
import java.security.Principal;
import java.util.List;
import java.util.Optional;

@SpringBootApplication
@EnableResourceServer
@EnableAuthorizationServer
@EnableDiscoveryClient
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringCloudAuthenticationServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringCloudAuthenticationServiceApplication.class, args);
    }

}

@RestController
@RequestMapping("/users")
@Slf4j
class UserController {

    @Autowired
    private UserService userService;

    @RequestMapping(value = "/current", method = RequestMethod.GET)
    public Principal getUser(Principal principal) {
        return principal;
    }

    @PreAuthorize("#oauth2.hasScope('server')")
    @RequestMapping(method = RequestMethod.POST)
    public void createUser(@Valid @RequestBody User user) {
        log.info("Creating user...");
        userService.create(user);
    }
}

@Configuration
class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuthUserDetailsServiceImpl oAuthUserDetailsService;

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests().anyRequest().authenticated()
                .and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.NEVER);
    }

    @Override
    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(oAuthUserDetailsService).passwordEncoder(encoder());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}

@Configuration
class OAuth2Config extends AuthorizationServerConfigurerAdapter {

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Bean
    public JwtAccessTokenConverter tokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("12345");
        return converter;
    }
    @Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(tokenConverter());
    }
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .tokenStore(tokenStore())
                .accessTokenConverter(tokenConverter());
    }
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // @formatter:off
        clients.inMemory()
                .withClient("browser")
                .secret(passwordEncoder.encode(""))
                .authorizedGrantTypes("refresh_token", "password", "authorization_code", "implicit")
                .scopes("ui", "read", "write", "trust")
                .accessTokenValiditySeconds(20000)
                .refreshTokenValiditySeconds(20000)
                .and()
                .withClient("account-service")
                .secret(passwordEncoder.encode("password"))
                .authorizedGrantTypes("client_credentials", "refresh_token", "password")
                .scopes("server")
                .accessTokenValiditySeconds(20000)
                .refreshTokenValiditySeconds(20000);
        // @formatter:on


    }
}


@Entity(name = "users")
class User implements UserDetails {

    @Id
    private String username;

    private String password;

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public List<GrantedAuthority> getAuthorities() {
        return null;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

@Repository
interface UserRepository extends CrudRepository<User, String> {

}

interface UserService {

    void create(User user);

}

@Service
class OAuthUserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return repository.findById(username).orElseThrow(()->new UsernameNotFoundException(username));
    }
}

@Service
@Slf4j
class UserServiceImpl implements UserService {

    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Autowired
    private UserRepository repository;

    @Override
    public void create(User user) {

        Optional<User> existing = repository.findById(user.getUsername());
        existing.ifPresent(it-> {throw new IllegalArgumentException("user already exists: " + it.getUsername());});

        String hash = encoder.encode(user.getPassword());
        user.setPassword(hash);

        repository.save(user);

        log.info("new user has been created: {}", user.getUsername());
    }
}