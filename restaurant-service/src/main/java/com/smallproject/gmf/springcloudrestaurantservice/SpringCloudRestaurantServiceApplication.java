package com.smallproject.gmf.springcloudrestaurantservice;

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
public class SpringCloudRestaurantServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringCloudRestaurantServiceApplication.class, args);
	}

}
@Data
class Restaurant {
    int id;
    String name;
    String address;
    String phone;

    public Restaurant(int id, String fName, String address, String phone) {
        this.id = id;
        this.name = fName;
        this.address = address;
        this.phone = phone;
    }

    public Restaurant() {
    }
}

@RestController
@RequestMapping("/restaurants")
class RestaurantController {
    public List<Restaurant> restaurants = new ArrayList<>();
    {
        Restaurant restaurant1 = new Restaurant(1,"Toid", "Bangalore", "9986254845");
        Restaurant restaurant2 = new Restaurant(2,"Kudla", "Mangalore", "8773268768");
        restaurants.add(restaurant1);
        restaurants.add(restaurant2);
    }

    @GetMapping("")
    public List<Restaurant> getUser() {
        return this.restaurants;
    }

}