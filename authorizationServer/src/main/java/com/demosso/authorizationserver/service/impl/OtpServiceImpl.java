package com.demosso.authorizationserver.service.impl;

import com.demosso.authorizationserver.domain.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.util.Random;

@Service
@Slf4j
public class OtpServiceImpl {

    public void generateOneTimePassword(String username) {
        String otp = generateOTP(8);
        //TODO add encoding
        //String encodedOTP = passwordEncoder.encode(otp);
        //TODO for now just log
        log.info("OTP = " + otp);
        //sendOTPEmail(user, otp);
    }

    public boolean verifyOneTimePassword(String username, String otp) {
        //TODO for now return always true
        return true;
    }

    //TODO move to another service
/*    private void sendOTPEmail(User user, String otp)
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
    }*/

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
        //TODO DB cleanup
    }
}
