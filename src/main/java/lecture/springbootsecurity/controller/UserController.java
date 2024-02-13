package lecture.springbootsecurity.controller;

import jakarta.servlet.http.HttpSession;
import lecture.springbootsecurity.dto.UserDTO;
import lecture.springbootsecurity.entity.UserEntity;
import lecture.springbootsecurity.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Slf4j // 로그 관련 메소드를 편리하게 사용할 수 있는 lombok 어노테이션
public class UserController {
    @Autowired
    UserService userService;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @GetMapping("")
    public String getAuth() {
        return "GET /auth";
    }

    @PostMapping("/signup")
    // restful한 api는 responseEntity 반환
    // ? : 와일드 카드 (어떤 값을 body에 담을지 모름)
    public ResponseEntity<?> registerUser(@RequestBody UserDTO userDTO) {
        try{
            UserEntity user = UserEntity.builder()
                    .email(userDTO.getEmail())
                    .username(userDTO.getUsername())
                    .password(passwordEncoder.encode(userDTO.getPassword())) // 암호화해서 넣기 (암호화는 서비스에서 객체 하나 더 만들어서 넣어도 상관없음)
                    .build();

            UserEntity responseUser = userService.create(user);

            // 사용자가 입력한 값을 그대로 받지 않기 위해 dto 객체 하나 더 생성
            UserDTO responseUserDTO = UserDTO.builder()
                    .email(responseUser.getEmail())
                    .username(responseUser.getUsername())
                    .id(responseUser.getId()).build();

            return ResponseEntity.ok().body(responseUserDTO);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/signin")
    // HttpSession 객체를 매개변수로 받으면 loginUser 요청에 대한 session이 저장됨
    public ResponseEntity<?> loginUser(HttpSession session, @RequestBody UserDTO userDTO) {
        try {
            UserEntity user = userService.login(userDTO.getEmail(), userDTO.getPassword());

            if (user == null) {
                throw new RuntimeException("login failed");
            }

            UserDTO responseUserDTO = UserDTO.builder()
                    .email(user.getEmail())
                    .username(user.getUsername())
                    .id(user.getId()).build();

//            log.info();
//            log.error();
            log.warn("session id {}", session.getId()); // 로그 중간에 변수를 넣고 싶을 땐 문자열 안에 중괄호 넣고 ,뒤에 변수 (여러 개 출력하고 싶을 땐 중괄호 추가)
            session.setAttribute("userId", user.getId());

            return ResponseEntity.ok().body(responseUserDTO);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}