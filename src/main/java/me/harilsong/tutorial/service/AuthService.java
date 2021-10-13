package me.harilsong.tutorial.service;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import me.harilsong.tutorial.dto.LoginDto;
import me.harilsong.tutorial.dto.TokenDto;
import me.harilsong.tutorial.dto.TokenRequestDto;
import me.harilsong.tutorial.entity.RefreshToken;
import me.harilsong.tutorial.jwt.JwtFilter;
import me.harilsong.tutorial.jwt.TokenProvider;
import me.harilsong.tutorial.repository.RefreshTokenRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public ResponseEntity<TokenDto> login(LoginDto loginDto) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginDto.getUsername(), loginDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject()
                .authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);

        // save refresh token
        RefreshToken refreshToken = RefreshToken.builder()
                .key(authentication.getName())
                .value(tokenDto.getRefreshToken())
                .build();

        refreshTokenRepository.save(refreshToken);

        HttpHeaders httpHeaders = setAuthorizationHeader(tokenDto);
        return new ResponseEntity<>(tokenDto, httpHeaders, HttpStatus.OK);
    }

    @Transactional
    public ResponseEntity<TokenDto> reissue(TokenRequestDto tokenRequestDto) {
        if (!tokenProvider.validateToken(tokenRequestDto.getRefreshToken())) {
            throw new JwtException("Refresh Token 이 유효하지 않습니다.");
        }

        Authentication authentication = tokenProvider.getAuthentication(tokenRequestDto.getAccessToken());
        RefreshToken refreshToken = refreshTokenRepository.findByKey(authentication.getName())
                .orElseThrow(() -> new RuntimeException("로그아웃된 사용자입니다."));

        if (!refreshToken.getValue().equals(tokenRequestDto.getRefreshToken())) {
            throw new RuntimeException("토큰의 유저 정보가 일치하지 않습니다.");
        }

        TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);

        // dirty checking
        refreshToken.updateValue(tokenDto.getRefreshToken());

        HttpHeaders httpHeaders = setAuthorizationHeader(tokenDto);

        return new ResponseEntity<>(tokenDto, httpHeaders, HttpStatus.OK);

    }

    private HttpHeaders setAuthorizationHeader(TokenDto tokenDto) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + tokenDto.getAccessToken());
        return httpHeaders;
    }

}
