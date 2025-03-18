package com.test.lsy.jwtreview2.auth;

import com.test.lsy.jwtreview2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByUsername(username)
            .map(PrincipalDetails::new)
            .orElseThrow(() -> {
                log.error("User not found: {}", username);
                return new UsernameNotFoundException("User not found: " + username);
            });
    }
}
