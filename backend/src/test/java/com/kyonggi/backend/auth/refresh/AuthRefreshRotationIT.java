package com.kyonggi.backend.auth.refresh;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import com.kyonggi.backend.auth.AbstractAuthIntegrationTest;
import com.kyonggi.backend.auth.token.domain.RefreshRevokeReason;
import com.kyonggi.backend.auth.token.domain.RefreshToken;
import com.kyonggi.backend.auth.token.support.TokenHashUtils;
import com.kyonggi.backend.global.ErrorCode;
import com.kyonggi.backend.support.AuthFlowSupport;
import com.kyonggi.backend.support.AuthHttpSupport;
import com.kyonggi.backend.support.AuthHttpSupport.LoginResult;
import com.kyonggi.backend.support.AuthHttpSupport.RefreshResult;

import jakarta.servlet.http.Cookie;


@DisplayName("[Auth][Refresh] 리프레시 토큰 로테이션 통합 테스트")
class AuthRefreshRotationIT extends AbstractAuthIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired TokenHashUtils tokenHashUtils;

    @Test 
    @DisplayName("로그인: refresh 쿠키 발급 + DB에는 refresh 해시 저장(세션 쿠키 정책)")
    void login_saves_refreshToken_hash_in_db_and_sets_cookie() throws Exception {
        //로그인 (rememberMe=false => 세션 쿠키 기대)
        LoginResult login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, false);
 
        // 응답에서 accessToken, refreshRaw 둘 다 있어야 함
        assertThat(login.refreshRaw()).isNotBlank();
        assertThat(login.accessToken()).isNotBlank();

        // DB에는 refresh 원문이 아니라 "hash"가 저장되어야 함 (보안상 원문 저장 금지)
        String hash = tokenHashUtils.sha256Hex(login.refreshRaw());
        Optional<RefreshToken> saved = refreshTokenRepository.findByTokenHash(hash);

        assertThat(saved).isPresent();     
        assertThat(saved.get().isRevoked()).isFalse(); // 아직 폐기되지 않은 토큰이어야 함
        assertThat(saved.get().isRememberMe()).isFalse(); // rememberMe=false로 저장돼야 함

        // setCookieLine = "KG_REFRESH=aaa.bbb.ccc; Path=/auth; HttpOnly; SameSite=Lax"
        String setCookieLine = AuthHttpSupport.findSetCookieLine(login.setCookieHeaders(), AuthHttpSupport.REFRESH_COOKIE);
       
        // Set-Cookie 정책 검사 (세션 쿠키라 Max-Age가 없어야 함)
        AuthHttpSupport.assertRefreshCookiePolicy(setCookieLine, false);
    }

    @Test
    @DisplayName("로그인(rememberMe): persistent refresh 쿠키(Max-Age) + DB rememberMe=true 저장")
    void login_with_rememberMe_sets_persistent_cookie_and_db_flag() throws Exception {
        // rememberMe=true 로그인
        LoginResult login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, true);

        // 쿠키 정책은 persistent여야 하므로 Max-Age가 있어야 함
        String setCookieLine = AuthHttpSupport.findSetCookieLine(login.setCookieHeaders(), AuthHttpSupport.REFRESH_COOKIE);
        AuthHttpSupport.assertRefreshCookiePolicy(setCookieLine, true);

        // DB에도 rememberMe 플래그가 true로 저장되어야 함
        String hash = tokenHashUtils.sha256Hex(login.refreshRaw());
        Optional<RefreshToken> saved = refreshTokenRepository.findByTokenHash(hash);

        assertThat(saved).isPresent();
        assertThat(saved.get().isRememberMe()).isTrue();
        assertThat(saved.get().isRevoked()).isFalse();
    }

    @Test
    @DisplayName("리프레시: 토큰 로테이션 수행(새 refresh 발급) + 기존 refresh ROTATED로 폐기")
    void refresh_rotates_token_and_revokes_old() throws Exception {
        // 로그인해서 old refresh를 얻는다
        LoginResult login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, false);
        String oldRaw = login.refreshRaw();
        
        // old refresh 해시(=DB에 저장된 키) & DB에 토큰 존재 유무 확인
        String oldHash = tokenHashUtils.sha256Hex(oldRaw);
        assertThat(refreshTokenRepository.findByTokenHash(oldHash)).isPresent();

        // POST: /auth/refresh 호출 (쿠키에 old refresh를 담아 보냄) -> refresh 토큰 새로 발급
        RefreshResult refreshed = AuthFlowSupport.refreshOk(mvc, oldRaw);
        String newRaw = refreshed.refreshRaw();

        assertThat(newRaw).isNotBlank();
        assertThat(newRaw).isNotEqualTo(oldRaw);

        // old 토큰은 revoked 처리되어야 한다. + reason=ROTATED
        var oldRowAfter = refreshTokenRepository.findByTokenHash(oldHash);
        assertThat(oldRowAfter).isPresent();
        assertThat(oldRowAfter.get().isRevoked()).isTrue();
        assertThat(oldRowAfter.get().getRevokeReason())
            .isEqualTo(RefreshRevokeReason.ROTATED.name());

        // new 토큰은 DB에 저장되어 있고 revoked=false 이어야 한다
        String newHash = tokenHashUtils.sha256Hex(newRaw);
        var newRow = refreshTokenRepository.findByTokenHash(newHash);
        assertThat(newRow).isPresent();
        assertThat(newRow.get().isRevoked()).isFalse();
    }

    @Test
    @DisplayName("리프레시: 쿠키 없음 → 401 REFRESH_INVALID")
    void refresh_without_cookie_returns_refresh_invalid() throws Exception {
        // 쿠키 없이 refresh 호출 => refresh 토큰이 없으므로 401 + REFRESH_INVALID
        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performRefresh(mvc, null),
                ErrorCode.REFRESH_INVALID
        );
    }

    @Test
    @DisplayName("리프레시: 미발급 refresh 토큰 → 401 REFRESH_INVALID")
    void refresh_with_unknown_token_returns_refresh_invalid() throws Exception {
        // 서버가 발급한 적 없는 refresh 토큰으로 호출 => 401 + REFRESH_INVALID
        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performRefresh(mvc, new Cookie(AuthHttpSupport.REFRESH_COOKIE, "definitely-not-issued-by-server")),
                ErrorCode.REFRESH_INVALID
        );
    }

    @Test
    @DisplayName("리프레시: 로테이션 후 구 refresh 재사용 시도 → 401 REFRESH_REUSED")
    void refresh_reusing_old_token_is_blocked() throws Exception {
        // 로그인해서 old refresh 획득
        var login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, false);
        String oldRaw = login.refreshRaw();

        //첫 refresh는 성공해서 로테이션이 일어난다
        AuthFlowSupport.refreshOk(mvc, oldRaw);
        
        // old refresh를 재사용하면 차단되어야 함 (REFRESH_REUSED)
        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performRefresh(mvc, new Cookie(AuthHttpSupport.REFRESH_COOKIE, oldRaw)),
                ErrorCode.REFRESH_REUSED
        );
    }

    @Test
    @DisplayName("리프레시: 로테이션 후에도 rememberMe 정책 유지(Max-Age 유지 + DB 플래그 유지)")
    void refresh_rotation_preserves_rememberMe_policy() throws Exception {
        // rememberMe=true로 로그인 => persistent 쿠키
        var login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, true);
        String oldRaw = login.refreshRaw();

        // POST: /auth/refresh 호출 -> new 토큰 발급
        RefreshResult refreshed = AuthFlowSupport.refreshOk(mvc, oldRaw);

        // 새 refresh 쿠키도 persistent(Max-Age 유지)여야 함
        String line = AuthHttpSupport.findSetCookieLine(refreshed.setCookieHeaders(), AuthHttpSupport.REFRESH_COOKIE);
        AuthHttpSupport.assertRefreshCookiePolicy(line, true);

        // DB에도 rememberMe=true가 유지되어야 한다
        String newHash = tokenHashUtils.sha256Hex(refreshed.refreshRaw());
        var newRow = refreshTokenRepository.findByTokenHash(newHash);

        assertThat(newRow).isPresent();
        assertThat(newRow.get().isRememberMe()).isTrue();
        assertThat(newRow.get().isRevoked()).isFalse();
    }
}
