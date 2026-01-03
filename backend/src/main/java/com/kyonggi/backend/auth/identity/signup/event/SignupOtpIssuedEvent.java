package com.kyonggi.backend.auth.identity.signup.event;

/**
 * OTP를 "발급/저장"한 뒤, 커밋이 끝나면 메일을 보내기 위한 이벤트
 * - OTP 6자리 코드 원문은 DB에 저장하지 않기 때문에, 메일 발송은
 *    이 이벤트에 code를 담아서 "트랜잭션 밖"에서 처리해야 한다.
 */
public record SignupOtpIssuedEvent (String email, String code) {}
