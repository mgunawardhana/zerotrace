package com.zerotrace.repository;

import com.zerotrace.entity.AuditLog;
import com.zerotrace.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findByUser(User user, Pageable pageable);

    List<AuditLog> findByUserAndAction(User user, String action);

    @Query("SELECT a FROM AuditLog a WHERE a.user = :user AND a.createdDate BETWEEN :start AND :end")
    List<AuditLog> findByUserAndDateRange(@Param("user") User user,
                                          @Param("start") LocalDateTime start,
                                          @Param("end") LocalDateTime end);

    @Query("SELECT a FROM AuditLog a WHERE a.suspicious = true AND a.createdDate > :since")
    List<AuditLog> findSuspiciousActivities(@Param("since") LocalDateTime since);

    @Query("SELECT a FROM AuditLog a WHERE a.ipAddress = :ip AND a.createdDate > :since")
    List<AuditLog> findByIpAddressAndDateAfter(@Param("ip") String ip, @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.user = :user AND a.action = :action AND a.createdDate > :since")
    long countByUserActionSince(@Param("user") User user, @Param("action") String action, @Param("since") LocalDateTime since);

    @Query("SELECT DISTINCT a.ipAddress FROM AuditLog a WHERE a.user = :user ORDER BY a.createdDate DESC")
    List<String> findRecentIpAddressesByUser(@Param("user") User user, Pageable pageable);
}