package com.smallproject.gmf.springclouduserservice;

import lombok.Data;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class SpringCloudUserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringCloudUserServiceApplication.class, args);
	}

}

@Data
class User {
    int id;
    String fName;
    String lName;
    String age;

    public User(int id, String fName, String lName, String age) {
        this.id = id;
        this.fName = fName;
        this.lName = lName;
        this.age = age;
    }

    public User() {
    }
}

@RestController
class UserController {
    public List<User> users = new ArrayList<>();
    {
        User user1 = new User(1,"First1", "Last2", "18");
        User user2 = new User(2,"First2", "Last2", "28");
        users.add(user1);
        users.add(user2);
    }

    @GetMapping("/list")
    public List<User> getUser() {
        return this.users;
    }

}