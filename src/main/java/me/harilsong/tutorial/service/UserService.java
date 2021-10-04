package me.harilsong.tutorial.service;

import java.util.Collections;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import me.harilsong.tutorial.dto.UserDto;
import me.harilsong.tutorial.entity.Authority;
import me.harilsong.tutorial.entity.User;
import me.harilsong.tutorial.repository.UserRepository;
import me.harilsong.tutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User signUp(UserDto userDto) {
        userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).ifPresent(user -> {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        });

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername()
                .flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
