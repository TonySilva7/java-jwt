package com.tony.jwtjava.service;

import com.tony.jwtjava.data.DetailUserData;
import com.tony.jwtjava.model.User;
import com.tony.jwtjava.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class DetailUserServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public DetailUserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByLogin(username);

        if (user.isEmpty()) {
            throw new UsernameNotFoundException("Usuário [" + username + "] não encontrado");
        }

        return new DetailUserData(user);
    }
}
