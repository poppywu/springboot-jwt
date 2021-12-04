package demo.security.controller;

import demo.security.model.AuthenticationRequest;
import demo.security.model.AuthenticationResponse;
import demo.security.service.JWTUtil;
import demo.security.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationRequestController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private MyUserDetailsService myUserDetailsService;
    @Autowired
    private JWTUtil jwtUtil;

    @PostMapping(path = "/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest){
        String username=authenticationRequest.getUsername();
        String password=authenticationRequest.getPassword();
        try{
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username,password));
        }catch (Exception error){
            error.printStackTrace();
            return new ResponseEntity<>(HttpStatus.NETWORK_AUTHENTICATION_REQUIRED);
        }
        final UserDetails userDetails=myUserDetailsService.loadUserByUsername(username);
        final String jwt=jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
}
