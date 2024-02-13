package lecture.springbootsecurity.security;
// 1. 세션 기반 인증 방식
// -- 로그인 성공 > session에 userId 저장
// -- 로그인 여부를 판단하고 싶을 때 > session에 userId가 존재하면 로그인을 한 사람, 존재하지 않으면 로그인하지 않은 사람으로 판단

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component // 클래스 자체를 스프링 컨테이너가 관리할 수 있도록 사용하는 어노테이션 (메소드는 @Bean)
@Slf4j
public class CustomAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            HttpSession session =  request.getSession(); // 해당 요청을 보낸 클라이언트의 세션값
            log.warn("session id {}", session.getId());
            Object userId = session.getAttribute("userId");

            log.warn("session id {} {}", session.getId(), userId);

            if( userId != null ) {
                // UsernamePasswordAuthenticationToken(유저 이름, 비번, 권한) -> 스프링 시큐리티에서 사용자의 정보를 담는 객체
                // 1. 사용자 정보를 담는 공간(토큰) 생성
                Authentication authentication = new UsernamePasswordAuthenticationToken(String.valueOf(userId), null, AuthorityUtils.NO_AUTHORITIES);

                // 2. SecurityContextHolder에 authentication 정보 담기(set)
                // SecurityContextHolder : 클라이언트의 요청 -> 응답 사이에 일시적으로 auth 정보를 저장할 수 있는 공간 (응답이 되면 자동으로 비워짐)
                SecurityContextHolder.getContext().setAuthentication(authentication);
//                SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            }

        } catch(Exception e) {
            log.error("filter error {}", e.getMessage());
        }

        filterChain.doFilter(request, response); // 위 필터 처리하고 다음 필터 실행하겠다.
    }
}
