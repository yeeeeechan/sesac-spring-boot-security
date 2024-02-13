package lecture.springbootsecurity.config;

import lecture.springbootsecurity.security.CustomAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

// SpringSequrity 3.x 버전 문법
@Configuration // spring 설정 클래스임을 나타내는 어노테이션
@EnableWebSecurity // 이 클래스는 Spring security를 사용함
public class WebSecurityConfig {
    
    // 필터 사용하기 위해 주입
    @Autowired
    CustomAuthFilter customAuthFilter;

    // 암호화
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean // 스프링 컨테이너에서 관리
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // springSequrity를 적용하면 기본적으로 모든 경로에 인증이 있어야 접근이 가능해짐.
        // 특정 경로에서 인증 없이 접근할 수 있도록 설정하기
        
        http
                .cors(Customizer.withDefaults()) // cors 필터 등록
                .csrf(CsrfConfigurer::disable) // post, put 요청을 허용한다.
                .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/auth/**").permitAll() // "/auth/~~~" 에 해당하는 요청은 모두 허가
//                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated() // 위에 나온 주소 말고 나머지 주소는 로그인이 필요하다.
        );

        // .permitAll() : 권한 없이 접속 가능
        // .authenticated() : 로그인이 필요하다.
        // .hasRole("권한? ex.ADMIN") : 특정 권한이 있어야 접속 가능
        // .anyRequest() : 앞에서 쓴 url 외에 나머지 모든 요청 (가장 마지막에 써야 함)

        // 만들어 둔 custom 필터 등록
        // UsernamePasswordAuthenticationFilter 필터 다음에 customAuthFilter를 등록하겠다.
        http.addFilterAfter(customAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // cors 설정
        config.setAllowCredentials(true); // 실제 응답을 보낼 때, 브라우저에게 자격 증명과 함께 요청을 보낼 수 있도록 허용합니다.
        config.setAllowedOriginPatterns(Arrays.asList("*")); // 모든 원본에서의 요청을 허용합니다.
        config.setAllowedMethods(Arrays.asList("HEAD","POST","GET","DELETE","PUT","PATCH")); // 허용할 HTTP 메서드를 설정합니다.
        config.setAllowedHeaders(Arrays.asList("*")); // 모든 헤더의 요청을 허용합니다.

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config); // 모든 경로에 대해 위에서 설정한 CORS 설정을 적용합니다.

        return source;
    };
}


// 2.x 버전 문법임!
//public class WebSecurityConfig extends SecurityConfigurerAdapter {
//    public configure() {}
//}