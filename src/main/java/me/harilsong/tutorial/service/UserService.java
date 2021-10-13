package me.harilsong.tutorial.service;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import me.harilsong.tutorial.entity.User;
import me.harilsong.tutorial.repository.UserRepository;
import me.harilsong.tutorial.util.SecurityUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername()
                .flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
