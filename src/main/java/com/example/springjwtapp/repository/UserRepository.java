package com.example.springjwtapp.repository;

import com.example.springjwtapp.model.UserModel;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<UserModel, Long> {
    UserModel findUserByUsername(String username);
}
