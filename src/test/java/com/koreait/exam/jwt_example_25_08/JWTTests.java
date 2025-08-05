package com.koreait.exam.jwt_example_25_08;

import com.koreait.exam.jwt_example_25_08.base.jwt.JwtProvider;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JWTTests {

    @Autowired
    private JwtProvider jwtProvider;

    @Value("${custom.jwt.secretKey}")
    private String secretKeyPlain; // 키 원문

    @Test
    @DisplayName("secretKey가 존재해야함")
    void t1() {
        assertThat(secretKeyPlain).isNotNull();
    }

    @Test
    @DisplayName("시크릿키 원문으로 hmac 암호화 알고리즘에 맞는 시크릿키 객체를 만들 수 있다.")
    void t2() {
        // 키를 Base64 인코딩 과정
        String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKeyPlain.getBytes());

        // Base64 인코딩된 키를 SecretKey 객체를 만든다.
        SecretKey secretKey = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());

        assertThat(secretKey).isNotNull();

    }

    @Test
    @DisplayName("JwtProvider 객체로 SecretKey 객체 생성")
    void t3() {
        SecretKey secretKey = jwtProvider.getSecretKey();

        assertThat(secretKey).isNotNull();
    }

    @Test
    @DisplayName("SecretKey 객체는 단 한번만 생성되어야 함")
    void t4() {
        SecretKey secretKey1 = jwtProvider.getSecretKey();
        SecretKey secretKey2 = jwtProvider.getSecretKey();

        assertThat(secretKey1 == secretKey2).isTrue();
    }

    @Test
    @DisplayName("accessToken 얻기")
    void t5() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id",1L);
        claims.put("username","admin123");

        // 지금(현재시각)으로부터 5시간의 유효기간을 가지는 토큰 생성
        String acceessToken = jwtProvider.genToken(claims,60 * 60 * 5);

        System.out.println("acceessToken: " + acceessToken);

        assertThat(acceessToken).isNotNull();
    }

    @Test
    @DisplayName("accessToken이 유효한지 체크(만료일 체크)")
    void t6() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id",1L);
        claims.put("username","admin123123");

        // 이미 만료된 토큰
        String acceessToken = jwtProvider.genToken(claims,60 * 60 * -5);

        System.out.println("acceessToken: " + acceessToken);

        assertThat(jwtProvider.verify(acceessToken)).isFalse();
    }

    @Test
    @DisplayName("accessToken을 통해서 claims 얻기")
    void t7() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id",1L);
        claims.put("username","admin123123");

        // 지금(현재시각)으로부터 5시간의 유효기간을 가지는 토큰 생성
        String acceessToken = jwtProvider.genToken(claims,60 * 60 * 5);

        System.out.println("acceessToken: " + acceessToken);

        assertThat(jwtProvider.verify(acceessToken)).isTrue();

        Map<String, Object> claimsFromToken = jwtProvider.getClaims(acceessToken);

        System.out.println("claimsFromToken: " + claimsFromToken);
    }

}
