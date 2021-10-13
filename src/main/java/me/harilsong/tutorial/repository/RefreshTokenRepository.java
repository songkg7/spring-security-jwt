package me.harilsong.tutorial.repository;

import java.util.Optional;
import me.harilsong.tutorial.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByKey(String key);

}
