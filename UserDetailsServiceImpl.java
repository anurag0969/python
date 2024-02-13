package com.Organics.LyncOrganic.config;


import com.Organics.LyncOrganic.entity.User;
import com.Organics.LyncOrganic.repository.User_Repo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Primary
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private User_Repo userRepo;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
            User theUser = userRepo.findByEmail(email);
            if (theUser!=null){
                return new CustomUserDetails(theUser);
            }
        throw new UsernameNotFoundException("user not available");
    }
}
