package LoginDemo.example.LoginDemo.Service;

import LoginDemo.example.LoginDemo.Dto.UserRegistrationDto;
import LoginDemo.example.LoginDemo.Model.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {
    User save(UserRegistrationDto registrationDto);
}
