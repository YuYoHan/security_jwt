package com.example.security_jwt.config.oauth;

import com.example.security_jwt.config.auth.PrincipalDetails;
import com.example.security_jwt.config.oauth.provider.GoogleUserInfo;
import com.example.security_jwt.config.oauth.provider.NaverUserInfo;
import com.example.security_jwt.config.oauth.provider.OAuth2UserInfo;
import com.example.security_jwt.model.User;
import com.example.security_jwt.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // registrationId로 어떤 OAuth로 로그인 했는지 확인가능
        log.info("clientRegistration : " + userRequest.getClientRegistration() );
        log.info("accessToken : " + userRequest.getAccessToken().getTokenValue() );

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 구글 로그인 버튼 클릭 →구글 로그인 창 → 로그인 완료 → code를 리턴(OAuth-Client라이브러리) → AccessToken 요청
        // userRequest 정보 → 회원 프로필 받아야함(loadUser함수 호출) → 구글로부터 회원 프로필을 받아준다.
        log.info("getAttributes : " + oAuth2User.getAttributes());

        // 회원가입을 강제로 진행
        OAuth2UserInfo oAuth2UserInfo = null;

        if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            log.info("네이버 로그인 요청");
            // 네이버는 response를 json으로 리턴을 해주는데 아래의 코드가 받아오는 코드다.
            // response={id=5SN-ML41CuX_iAUFH6-KWbuei8kRV9aTHdXOOXgL2K0, email=zxzz8014@naver.com, name=전혜영}
            // 위의 정보를 NaverUserInfo에 넘기면
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        } else {
            log.info("우리는 구글과 네이버만 지원합니다.");
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String userName = provider + "_" + providerId; // google_109742856182916427686
        String password = bCryptPasswordEncoder.encode("get");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User byUserName = userRepository.findByUserName(userName);

        if(byUserName == null) {
            log.info("OAuth 로그인이 최초입니다.");
            byUserName = User.builder()
                    .userName(userName)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

            userRepository.save(byUserName);
        } else {
            log.info("로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어 있습니다.");
        }
        return new PrincipalDetails(byUserName, oAuth2User.getAttributes());
    }
}

