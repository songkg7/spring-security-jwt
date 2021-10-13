package me.harilsong.tutorial.controller;

import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.harilsong.tutorial.dto.LoginDto;
import me.harilsong.tutorial.dto.TokenDto;
import me.harilsong.tutorial.dto.TokenRequestDto;
import me.harilsong.tutorial.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {
        return authService.login(loginDto);
    }

    @PostMapping("/reissue")
    public ResponseEntity<TokenDto> reissue(@RequestBody TokenRequestDto tokenRequestDto) {
        return authService.reissue(tokenRequestDto);
    }
}
