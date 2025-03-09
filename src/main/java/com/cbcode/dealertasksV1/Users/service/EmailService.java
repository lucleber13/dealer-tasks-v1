package com.cbcode.dealertasksV1.Users.service;

public interface EmailService {
    void sendEmail(String to, String subject, String text);

    void sendPasswordResetEmail(String toEmail, String resetLink);
}
