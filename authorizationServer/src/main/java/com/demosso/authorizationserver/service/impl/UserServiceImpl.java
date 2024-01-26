package com.demosso.authorizationserver.service.impl;

import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.repository.UserRepository;
import com.demosso.authorizationserver.service.ClientService;
import com.demosso.authorizationserver.service.UserService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.util.Random;


@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
	private final UserRepository repository;
	private final JavaMailSender mailSender;
	private final ClientService clientService;

	@Override
	public User getByUsername(String username) {
		if (!StringUtils.hasText(username)) {
			return null;
		}

		//TODO here we don't know the client. For now let's pick demo-client as the default one
		RegisteredClient client = clientService.getByClientId("demo-client");
		return getByUsernameAndClient(username,client.getId());

		//return repository.findByUsername(username).orElse(null);
	}

	@Override
	public User getByUsernameAndClient(String username, String clientId) {
		if (!StringUtils.hasText(username) || !StringUtils.hasText(clientId)) {
			return null;
		}

		return repository.findByUsernameAndClientId(username,clientId).orElse(null);
	}

	@Override
	public User save(User entity) {
		return repository.save(entity);
	}


	public void generateOneTimePassword(User user) throws MessagingException, UnsupportedEncodingException {
		String otp = generateOTP(8);
		//TODO add encoding
		//String encodedOTP = passwordEncoder.encode(otp);

		user.setOtp(otp);
		user.setOtpRequestedAt(LocalDateTime.now());
		save(user);

		sendOTPEmail(user, otp);
	}

	//TODO move to another service
	public void sendOTPEmail(User user, String otp)
			throws UnsupportedEncodingException, MessagingException {
		MimeMessage message = mailSender.createMimeMessage();
		MimeMessageHelper helper = new MimeMessageHelper(message);

		helper.setFrom("demo@shopme.com", "Demo");

		//TODO get user email instead of hardcoded one
		//helper.setTo(user.getEmail());
		helper.setTo("dcharilas@gmail.com");

		String subject = "Here's your One Time Password (OTP) - Expire in 5 minutes!";
		String content = "<p>Hello </p>"
				+ "<p>For security reason, you're required to use the following "
				+ "One Time Password to login:</p>"
				+ "<p><b>" + otp + "</b></p>"
				+ "<br>"
				+ "<p>Note: this OTP is set to expire in 5 minutes.</p>";

		helper.setSubject(subject);
		helper.setText(content, true);
		mailSender.send(message);
	}

	//TODO move to another class
	private String generateOTP(int length) {
		String numbers = "0123456789";
		Random rndm_method = new Random();
		char[] otp = new char[length];
		for (int i = 0; i < length; i++) {
			otp[i] = numbers.charAt(rndm_method.nextInt(numbers.length()));
		}
		return new String(otp);
	}

	public void clearOTP(User user) {
		user.setOtp(null);
		user.setOtpRequestedAt(null);
		save(user);
	}
}
