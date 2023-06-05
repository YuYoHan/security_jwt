package com.example.security_jwt.config;

import com.example.security_jwt.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/*
*       1. 코드받기(인증)
*       2. 엑세스 토큰(권한)
*       3. 사용자 프로필 정보를 가져오고
*       4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
*       4-2. 이메일, 전화번호, 이름, 아이디만 구글 정보에 있고 쇼핑몰을 가입하려고 하면
*            집 주소 등이 더 필요할 경우 자동으로 회원가입을 하는 것이 아니라 추가적인
*            회원가입 창이 나와서 회원가입을 해야한다. 추가적인 정보가 필요없으면 자동으로 회원가입
* */

@Configuration
// 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
@EnableWebSecurity
// secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;


//    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
//    @Bean
//    public BCryptPasswordEncoder encoder() {
//        return new BCryptPasswordEncoder();
//    }

    /*
    *   @Override
    *   protected void cofigure(HttpSecurity http) throws Exception{}
    *
    *   ↓아래와 같이 바뀜↓
    * */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // .csrf() : Cross site Request forgery로 사이즈간 위조 요청인데
        // 즉 정상적인 사용자가 의도치 않은 위조요청을 보내는 것을 의미한다.
        /*
        *   예를 들어 A라는 도메인에서, 인증된 사용자 H가 위조된
        *   request를 포함한 link, email을 사용하였을 경우(클릭, 또는 사이트 방문만으로도),
        *   A 도메인에서는 이 사용자가 일반 유저인지, 악용된 공격인지 구분할 수가 없다.
        * */
         http.csrf().disable();
         // 특정한 경로에 특정한 권한을 가진 사용자만 접근할 수 있도록 아래의 메소드를 이용합니다.
         http.authorizeRequests()
                 // antMatchers()는 특정한 경로를 지정합니다.
                 // antMatchers 메소드는 요청 타입을 의미
                 // URL이 user뒤에 오는 모든 것을 .authenticated() 메소드가 적용되는데
                 // 해당 메소드는 로그인 된 상태를 의미합니다.
                 // 그러므로 /user/*는 로그인된 상태에서만 접근 가능합니다.
                 .antMatchers("/user/**").authenticated()
                 // hasRole()은 시스템상에서 특정 권한을 가진 사람만이 접근할 수 있음
                 .antMatchers("/manager/**").access(
                         "hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                 .antMatchers("/admin/**").access(
                         "hasRole('ROLE_ADMIN')")
                 .anyRequest().permitAll()
                 .and()
                 .formLogin()
                 .loginPage("/loginForm")
                 // /login 주소가 호출이되면 시큐리티가 낚아채서 대신 로그인을 진행합니다.
                 // 이걸 추가하면 컨트롤러에 /login을 만들지 않아도 된다.
                 .loginProcessingUrl("/login")
                 .defaultSuccessUrl("/")
                 .and()
                 .oauth2Login()
                 .loginPage("/loginForm") // 구글 로그인이 완료된 후 후처리 필요
                 // OAuth2 로그인 성공 이후 사용자 정보를 가져올 때 설정 담당
                 .userInfoEndpoint()
                 // OAuth2 로그인 성공 시, 후작업을 진행할 서비스
                 .userService(principalOauth2UserService);

         return http.build();

    }
}
