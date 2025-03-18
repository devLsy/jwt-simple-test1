package com.test.lsy.jwtreview2.service;

import com.test.lsy.jwtreview2.model.User;
import com.test.lsy.jwtreview2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;

    /**
     * 저장
     * @param user
     * @return
     */
    public Long save(User user) {
        return repository.save(user).getId();
    }
}
