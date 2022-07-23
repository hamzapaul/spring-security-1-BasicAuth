package paul.com.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import paul.com.demo.model.UserPermission;
import paul.com.demo.model.UserRole;

import static paul.com.demo.model.UserPermission.COURSE_WRITE;
import static paul.com.demo.model.UserRole.*;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class BasicAuthSecurity {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public BasicAuthSecurity(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()  //spring default security
                .authorizeHttpRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())   //Role based authentication
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())    //Permission based
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
        return http.build();
    }

    //In-Memory Authentication
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails userDetails = User.builder()
                .username("Hamza")
                .password(passwordEncoder.encode("password"))
                .roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails sajid = User.builder()
                .username("Sajid")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMIN.name())   //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails paul = User.builder()
                .username("Paul")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                userDetails,
                sajid,
                paul
        );
    }
}
