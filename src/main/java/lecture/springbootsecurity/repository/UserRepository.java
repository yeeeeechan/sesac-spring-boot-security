package lecture.springbootsecurity.repository;

import lecture.springbootsecurity.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    UserEntity findByEmailAndPassword(String email, String password);
    UserEntity findByEmail(String email);
    Boolean existsByEmail(String email);
}
