package com.cbcode.dealertasksV1.Users.service.impl;

import com.cbcode.dealertasksV1.Users.service.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailServiceImpl.class);
    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public EmailServiceImpl(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    /**
     * @param to the email address of the recipient of the email message
     * @param subject the subject of the email message to be sent to the recipient
     * @param text the text of the email message to be sent to the recipient
     */
    @Override
    public void sendEmail(String to, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        try {
            mailSender.send(message);
        } catch (MailException e) {
            logger.error("Failed to send email ", e);
            throw new RuntimeException("Failed to send email " ,e);
        }
    }

    /**
     * Sends a password reset email to the user.
     * @param toEmail the email address of the user
     * @param resetLink the link to reset the password
     */
    @Override
    public void sendPasswordResetEmail(String toEmail, String resetLink) {
        try {
            logger.info("Sending password reset email to user: {}", toEmail);
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("Password Reset Request");
            message.setText("To reset your password, click the link below:\n\n" +
                    // TODO: Update the reset link to point to the frontend reset password page
                    "http://localhost:8080/api/v1/auth/reset-password?token=" + resetLink + "\n\n" +
                    "If you didn't request a password reset, please ignore this email.\n\n" +
                    "This link will expire in 15 minutes.");
            mailSender.send(message);
        } catch (MailException e) {
            logger.error("Failed to send email ", e);
            throw new RuntimeException("Failed to send email " ,e);
        }
    }
}
