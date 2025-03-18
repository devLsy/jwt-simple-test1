package com.test.lsy.jwtreview2.repository;

import com.test.lsy.jwtreview2.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    public Optional<User> findByUsername(String username);
}
