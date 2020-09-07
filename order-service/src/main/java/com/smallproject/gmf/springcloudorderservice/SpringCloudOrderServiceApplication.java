package com.smallproject.gmf.springcloudorderservice;

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
public class SpringCloudOrderServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringCloudOrderServiceApplication.class, args);
	}

}

@Data
class Order {
    int id;
    int restaurantId;
    int userId;
    String items;

    public Order(int id, int restaurantId, int userId, String items) {
        this.id = id;
        this.restaurantId = restaurantId;
        this.userId = userId;
        this.items = items;
    }

    public Order() {
    }
}

@RestController
@RequestMapping("/orders")
class OrderController {
    public List<Order> orders = new ArrayList<>();
    {
        Order order1 = new Order(1,1, 1, "rice, dal");
        Order order2 = new Order(2,2, 2, "burger, pizza");
        orders.add(order1);
        orders.add(order2);
    }

    @GetMapping("")
    public List<Order> getUser() {
        return this.orders;
    }

}