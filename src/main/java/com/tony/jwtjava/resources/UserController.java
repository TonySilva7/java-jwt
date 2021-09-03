package com.tony.jwtjava.resources;

import com.tony.jwtjava.model.User;
import com.tony.jwtjava.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.encoder = passwordEncoder;
    }

    @GetMapping("/all")
    public ResponseEntity<List<User>> findAll() {

        return ResponseEntity.ok(userRepository.findAll());
    }

    @PostMapping("/save")
    public ResponseEntity<User> save(@RequestBody User user) {
        user.setPassword(encoder.encode(user.getPassword()));

        return ResponseEntity.ok(userRepository.save(user));
    }

    @GetMapping("/validate-password")
    public ResponseEntity<Boolean> myValidatePassword(@RequestParam String login, @RequestParam String password) {
        Optional<User> optlUser = userRepository.findByLogin(login);

        if (optlUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(false);
        }

        User user = optlUser.get();
        boolean isValid = encoder.matches(password, user.getPassword());

        HttpStatus myStatus = (isValid) ? HttpStatus.OK : HttpStatus.UNAUTHORIZED;

        return ResponseEntity.status(myStatus).body(isValid);
    }
}
