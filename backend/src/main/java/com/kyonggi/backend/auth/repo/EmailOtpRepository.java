package com.kyonggi.backend.auth.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;

import jakarta.persistence.LockModeType;

@Repository
public interface EmailOtpRepository extends JpaRepository<EmailOtp, Long> {
    Optional<EmailOtp> findByEmailAndPurpose(String email, OtpPurpose purpose);

    /**
     * 동시 요청/검증 방지용 "Row Lock" 조회 (비관적 락)
     * 
     * @Lock(PESSIMISTIC_WRITE)의 의미:
     * - DB에 "쓰기 락"을 걸고 해당 row를 가져옴
     * - 같은 (email, purpose)의 row를 다른 트랜잭션이 동시에 가져가서 수정하려 하면
     *   -> 먼저 잡은 트랜잭션이 끝날 때까지 대기한다.
     * 
     * 즉, OTP 로직에서 이런 동시성 문제를 막기 위한 장치:
     * - 같은 이메일로 OTP request가 동시에 2개 들어와서 둘 다 "쿨다운 통과 / 일일제한 통과"를 해버리고
     *   결과적으로 메일이 2통 가는 문제가 발생한다.
     * 
     * 중요한 한계(실무 포인트):
     * - "row가 이미 존재할 때"는 락이 걸린다.
     * - 하지만 row가 아예 없는 최초 요청(처음 생성)에서는 잠글 대상 row가 없어서 동시에 insert 경쟁이 날 수 있다.
     *   → 그래서 실전에서는 (email, purpose) 유니크 제약을 DB에 걸고,
     *     insert 충돌(DataIntegrityViolationException) 나면 재조회/재시도하는 패턴을 같이 쓴다.
     * 
     * - 이 메서드는 반드시 @Transactional 안에서 호출되어야 락이 의미가 있다.
     *   (트랜잭션이 끝나는 순간 락이 풀리기 때문)
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select e from EmailOtp e where e.email = :email and e.purpose = :purpose")
    Optional<EmailOtp> findByEmailAndPurposeForUpdate(
            @Param("email") String email,
            @Param("purpose") OtpPurpose purpose
    );
}
