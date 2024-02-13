package lecture.springbootsecurity.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/todo")
public class TodoController {
    @GetMapping("")
    public String getTodo(@AuthenticationPrincipal String userId) {
        // @AuthenticationPrincipal
        // : SecurityContextHolder.getContext().getAuthentication().getPrincipal(); 값을 자동으로 userId에 할당해 준다.

        return "GET /todo by userId " + userId;
    }
}
