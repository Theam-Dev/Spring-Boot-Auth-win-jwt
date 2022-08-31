package com.example.springjwtapp.controller;

import com.example.springjwtapp.model.UserModel;
import com.example.springjwtapp.repository.UserRepository;
import com.example.springjwtapp.service.JwtUserDetailsService;
import com.example.springjwtapp.util.JwtTokenUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    final UserRepository userRepository;
    final AuthenticationManager authenticationManager;
    final JwtUserDetailsService userDetailsService;
    final JwtTokenUtil jwtTokenUtil;
    public AuthenticationController(UserRepository userRepository, AuthenticationManager authenticationManager,
                                    JwtUserDetailsService userDetailsService, JwtTokenUtil jwtTokenUtil) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
    }
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody UserModel userModel) {
        Map<String, Object> responseMap = new HashMap<>();
        try {
            Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userModel.getUsername()
                    , userModel.getPassword()));
            if (auth.isAuthenticated()) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(userModel.getUsername());
                String token = jwtTokenUtil.generateToken(userDetails);
                responseMap.put("error", false);
                responseMap.put("message", "Logged In");
                responseMap.put("token", token);
                return ResponseEntity.ok(responseMap);
            } else {
                responseMap.put("error", true);
                responseMap.put("message", "Invalid Credentials");
                return ResponseEntity.status(401).body(responseMap);
            }
        } catch (DisabledException e) {
            e.printStackTrace();
            responseMap.put("error", true);
            responseMap.put("message", "User is disabled");
            return ResponseEntity.status(500).body(responseMap);
        } catch (BadCredentialsException e) {
            responseMap.put("error", true);
            responseMap.put("message", "Invalid Credentials");
            return ResponseEntity.status(401).body(responseMap);
        } catch (Exception e) {
            e.printStackTrace();
            responseMap.put("error", true);
            responseMap.put("message", "Something went wrong");
            return ResponseEntity.status(500).body(responseMap);
        }
    }
    @PostMapping("/register")
    public ResponseEntity<Object> saveUser(@RequestBody UserModel userModel) {
        Map<String, Object> responseMap = new HashMap<>();
        UserModel user = new UserModel();
        user.setUsername(userModel.getUsername());
        user.setEmail(userModel.getEmail());
        user.setPassword(new BCryptPasswordEncoder().encode(userModel.getPassword()));
        user.setRole("USER");
        UserDetails userDetails = userDetailsService.createUserDetails(userModel.getUsername(), userModel.getPassword());
        String token = jwtTokenUtil.generateToken(userDetails);
        userRepository.save(user);
        responseMap.put("error", false);
        responseMap.put("data", user);
        responseMap.put("message", "Account created successfully");
        responseMap.put("token", token);
        return ResponseEntity.ok(responseMap);
    }
    @GetMapping("/user")
    public Map<String, Object> getUserName() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> userMap = new HashMap<>();
        userMap.put("username", authentication.getName());
        userMap.put("error", false);
        return userMap;
    }
}
