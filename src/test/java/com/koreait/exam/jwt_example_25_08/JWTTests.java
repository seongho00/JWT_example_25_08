package com.koreait.exam.jwt_example_25_08;

import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;

import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JWTTests {
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

}
