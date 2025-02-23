package ru.examples.test.controller;

import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {

    @GetMapping("/text")
    public String processEvent() {
        if (checkRole("SUPER_ROLE")) {
            return "Super text";
        }
        return "Text";
    }

    private boolean checkRole(String role) {
        val auth = SecurityContextHolder.getContext().getAuthentication();
        return auth.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(role));
    }
}
