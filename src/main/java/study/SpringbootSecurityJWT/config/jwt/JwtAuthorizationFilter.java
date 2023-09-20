package study.SpringbootSecurityJWT.config.jwt;


//권한이나 인증이 필요한 특정 주소를 요청했을때 BasicAuthenticationFilter가 적용됨

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import study.SpringbootSecurityJWT.config.auth.PrincipalDetails;
import study.SpringbootSecurityJWT.model.User;
import study.SpringbootSecurityJWT.repository.UserRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }
    //인증이나 권한이 필요한 주소요청이 있을때 해당 필터를 타게 됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("JwtAuthorizationFilter : 인증이나 권한이 필요한 주소 요청됨");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);

//        super.doFilterInternal(request, response, chain);

        //header값 확인하기
        if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        //JWT 토큰 검증하기
        String jwtToken = jwtHeader.replace(JwtProperties.TOKEN_PREFIX, "");
        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username")
                .asString();

        //검증이 제대로 됨
        if (username != null) {
            User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("유저가 존재하지 않습니다."));
            PrincipalDetails principalDetails = new PrincipalDetails(user);
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails.getUsername(), null, principalDetails.getAuthorities());

            //authenticationManager로 로그인이 아닌 강제로 SecurityContext에 등록하기
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }

    }
}
