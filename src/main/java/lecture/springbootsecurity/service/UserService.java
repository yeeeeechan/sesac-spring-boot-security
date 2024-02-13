package lecture.springbootsecurity.service;

import lecture.springbootsecurity.entity.UserEntity;
import lecture.springbootsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public UserEntity create(UserEntity userEntity){ // 회원가입 할 때 사용될 메소드
        if(userEntity == null ){
            throw new RuntimeException("entity null");
        }

        // 중복 이메일 불가
        String email = userEntity.getEmail();

        if(userRepository.existsByEmail(email)){
            throw new RuntimeException("이미 존재하는 이메일");
        }

        return userRepository.save(userEntity);
    }

    // 암호화 적용 전
//    public UserEntity login(String email, String password) {
//        return userRepository.findByEmailAndPassword(email, password);
//    }

    // 암호화 적용 후
    public UserEntity login(String email, String password) {
        UserEntity searchUser = userRepository.findByEmail(email);

        // .matches() : 앞에 온 매개변수를 암호화해서 뒤 매개변수와 비교함
        if(searchUser != null && passwordEncoder.matches(password, searchUser.getPassword())) {
            return searchUser;
        }
        return null;
    }
}
