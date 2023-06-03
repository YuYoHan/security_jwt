package com.example.security_jwt.repository;

import com.example.security_jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

// CRUD 함수를 JpaRepository가 들고 있음
// @Repository라는 어노테이션이 없어도 IoC가 됩니다.
// 그이유는 JpaRepository를 상속했기 때문이다.
public interface UserRepository extends JpaRepository<User, Integer> {
    // findBy규칙 → Username 문법
    // select * from user where username = 1?
    User findByUserName(String username);
    List<User> findByUserNameAndPassword(String username, String password);

}
