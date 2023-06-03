package com.example.security_jwt.controller;

import com.example.security_jwt.config.auth.PrincipalDetails;
import com.example.security_jwt.model.User;
import com.example.security_jwt.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Controller
@Log4j2
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String loginTest(Authentication authentication,
                                          @AuthenticationPrincipal OAuth2User oAuth) {  // DI(의존성 주입)
        log.info("/test/login-------------------");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("authentication : " + oAuth2User.getAttributes());
        log.info("oauth2User : " + oAuth.getAttributes());
        return "Oauth 세션 정보 확인하기";
    }




    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        log.info(user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        return "index";
    }


    @PostMapping("/login")
    public String login(User user, Model model) {
        String name = user.getUserName();
        String pw = user.getPassword();

        List<User> byUserNameAndPassword = userRepository.findByUserNameAndPassword(name, pw);

        if(byUserNameAndPassword != null) {
            log.info(byUserNameAndPassword);
            for (User user2: byUserNameAndPassword
            ) {
                model.addAttribute("loginUser" + user2.getUserName());
            }
            return "/index";
        } else {
            log.info("없는 아이디 입니다.");
            return "/joinForm";
        }
    }

    // OAuth 로그인 해도 PrincipalDetails
    // 일반 로그인을 해도 PrincipalDetails
    @GetMapping("/user")
    // PrincipalDetails로 받으면 Oauth로 받든 일반적인 로그인으로 받든 전부 받을 수 있다.
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails : " + principalDetails.getUser());
        return "user";
    }


    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public  @ResponseBody String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public  @ResponseBody String data() {
        return "데이터정보";
    }
}
