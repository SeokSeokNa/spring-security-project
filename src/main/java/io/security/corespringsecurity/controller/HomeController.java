package io.security.corespringsecurity.controller;


import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
	
	@GetMapping(value="/")
	public String home() throws Exception {
		return "home";
	}

	@Bean
	public ModelMapper createModelMapper() {
		return new ModelMapper();
	}
}
