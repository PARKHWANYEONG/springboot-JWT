package study.SpringbootSecurityJWT.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.SpringbootSecurityJWT.config.auth.PrincipalDetails;
import study.SpringbootSecurityJWT.model.User;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");
        try {
            //1. request에서 objectMapper를 사용해서 username, password 받기
            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(request.getInputStream(), User.class);

            //2. 받은 username, password로 UsernamePasswordAuthenticationToken을 생성해서
            //   authenticationManager로 authenticate()를 실행하면
            //   PrincipalDetailsService의 loadUserByUsername가 실행되어 토큰의 username으로 데이터베이스에서 조회후
            //   내부의 PasswordEncoder(설정안했을경우 기본값은 bcrypt)로 토큰의 password를 인코딩해서
            //   데이터베이스에서 조회한 비밀번호와 일치하는지 확인하여 Authentication객체 생성
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            //로그인 확인
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 : " + principalDetails.getUser());

            //4. Authentication객체를 return 하면서 세션 내부에 있는 SecurityContext에 등록
            //   JWT토큰을 사용할때 SecurityContext생성 필수적이지 않음 (security의 권한 관리 기능을 위해 추가)
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 함수 실행 후 인증이 정상적으로 완료되었으면 successfulAuthentication 함수가 실행
    // 여기서 JWT토큰 생성후 request요청한 사용자에게 JWT토큰을 response해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication실행 완료 (인증이 되었다는뜻!)");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA방식이 아닌 Hash암호방식
        String jwtToken = JWT.create()
                .withSubject("hwan토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING,JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}
