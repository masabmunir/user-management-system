const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

class EmailService {
  constructor() {
    this.transporter = null;
    this.initializeTransporter();
  }

  // Initialize email transporter based on configuration
  initializeTransporter() {
    const emailProvider = process.env.EMAIL_PROVIDER || 'smtp';

    switch (emailProvider.toLowerCase()) {
      case 'sendgrid':
        this.transporter = nodemailer.createTransport({
          host: 'smtp.sendgrid.net',
          port: 587,
          secure: false,
          auth: {
            user: 'apikey',
            pass: process.env.SENDGRID_API_KEY
          }
        });
        break;

      case 'mailgun':
        this.transporter = nodemailer.createTransport({
          host: process.env.MAILGUN_SMTP_HOST || 'smtp.mailgun.org',
          port: 587,
          secure: false,
          auth: {
            user: process.env.MAILGUN_SMTP_USER,
            pass: process.env.MAILGUN_SMTP_PASS
          }
        });
        break;

      case 'gmail':
        this.transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
          }
        });
        break;

      default:
        // SMTP configuration
        this.transporter = nodemailer.createTransport({
          host: process.env.SMTP_HOST || 'smtp.gmail.com',
          port: process.env.SMTP_PORT || 587,
          secure: process.env.SMTP_SECURE === 'true',
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
          }
        });
    }

    logger.info(`Email service initialized with provider: ${emailProvider}`);
  }

  // Send verification email
  async sendVerificationEmail(email, verificationToken, userName) {
    try {
      const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email/${verificationToken}`;
      
      const mailOptions = {
        from: `"${process.env.APP_NAME || 'User Management System'}" <${process.env.EMAIL_FROM}>`,
        to: email,
        subject: 'Verify Your Email Address',
        html: this.getVerificationEmailTemplate(userName, verificationUrl),
        text: `Hi ${userName},\n\nPlease verify your email by clicking the following link:\n${verificationUrl}\n\nThis link will expire in 24 hours.\n\nIf you didn't create an account, please ignore this email.`
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`Verification email sent to ${email}`);
      return { success: true, messageId: result.messageId };

    } catch (error) {
      logger.error(`Failed to send verification email to ${email}:`, error.message);
      throw new Error('Failed to send verification email');
    }
  }

  // Send password reset email
  async sendPasswordResetEmail(email, resetToken, userName) {
    try {
      const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password/${resetToken}`;
      
      const mailOptions = {
        from: `"${process.env.APP_NAME || 'User Management System'}" <${process.env.EMAIL_FROM}>`,
        to: email,
        subject: 'Password Reset Request',
        html: this.getPasswordResetEmailTemplate(userName, resetUrl),
        text: `Hi ${userName},\n\nYou requested to reset your password. Click the link below to reset it:\n${resetUrl}\n\nThis link will expire in 1 hour.\n\nIf you didn't request this, please ignore this email and your password will remain unchanged.`
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`Password reset email sent to ${email}`);
      return { success: true, messageId: result.messageId };

    } catch (error) {
      logger.error(`Failed to send password reset email to ${email}:`, error.message);
      throw new Error('Failed to send password reset email');
    }
  }

  // Send welcome email after verification
  async sendWelcomeEmail(email, userName) {
    try {
      const dashboardUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/dashboard`;
      
      const mailOptions = {
        from: `"${process.env.APP_NAME || 'User Management System'}" <${process.env.EMAIL_FROM}>`,
        to: email,
        subject: 'Welcome! Your Account is Active',
        html: this.getWelcomeEmailTemplate(userName, dashboardUrl),
        text: `Hi ${userName},\n\nWelcome to ${process.env.APP_NAME || 'User Management System'}!\n\nYour account has been successfully verified and is now active.\n\nYou can now log in and access your dashboard at:\n${dashboardUrl}\n\nThank you for joining us!`
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`Welcome email sent to ${email}`);
      return { success: true, messageId: result.messageId };

    } catch (error) {
      logger.error(`Failed to send welcome email to ${email}:`, error.message);
      throw new Error('Failed to send welcome email');
    }
  }

  // Send password changed confirmation
  async sendPasswordChangedEmail(email, userName) {
    try {
      const supportUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/support`;
      
      const mailOptions = {
        from: `"${process.env.APP_NAME || 'User Management System'}" <${process.env.EMAIL_FROM}>`,
        to: email,
        subject: 'Password Changed Successfully',
        html: this.getPasswordChangedEmailTemplate(userName, supportUrl),
        text: `Hi ${userName},\n\nThis is a confirmation that your password has been changed successfully.\n\nIf you didn't make this change, please contact our support team immediately at:\n${supportUrl}\n\nFor your security, we recommend:\n- Using a strong, unique password\n- Enabling two-factor authentication\n- Never sharing your password with anyone`
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`Password changed confirmation sent to ${email}`);
      return { success: true, messageId: result.messageId };

    } catch (error) {
      logger.error(`Failed to send password changed email to ${email}:`, error.message);
      throw new Error('Failed to send password changed email');
    }
  }

  // Send account activation email (for bulk imported users)
  async sendAccountActivationEmail(email, tempPassword, userName) {
    try {
      const loginUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login`;
      
      const mailOptions = {
        from: `"${process.env.APP_NAME || 'User Management System'}" <${process.env.EMAIL_FROM}>`,
        to: email,
        subject: 'Your Account Has Been Created',
        html: this.getAccountActivationEmailTemplate(userName, tempPassword, loginUrl),
        text: `Hi ${userName},\n\nAn account has been created for you.\n\nYour temporary credentials:\nEmail: ${email}\nPassword: ${tempPassword}\n\nPlease log in at ${loginUrl} and change your password immediately.\n\nFor security reasons, please change your password as soon as you log in.`
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`Account activation email sent to ${email}`);
      return { success: true, messageId: result.messageId };

    } catch (error) {
      logger.error(`Failed to send account activation email to ${email}:`, error.message);
      throw new Error('Failed to send account activation email');
    }
  }

  // Email verification template
  getVerificationEmailTemplate(userName, verificationUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Verify Your Email</h1>
          </div>
          <div class="content">
            <p>Hi <strong>${userName}</strong>,</p>
            <p>Thank you for registering! Please verify your email address to activate your account.</p>
            <div style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </div>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; color: #667eea;">${verificationUrl}</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you didn't create an account, you can safely ignore this email.</p>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} ${process.env.APP_NAME || 'User Management System'}. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Password reset template
  getPasswordResetEmailTemplate(userName, resetUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; padding: 12px 30px; background: #f5576c; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }
          .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Reset Your Password</h1>
          </div>
          <div class="content">
            <p>Hi <strong>${userName}</strong>,</p>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <div style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </div>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; color: #f5576c;">${resetUrl}</p>
            <div class="warning">
              <strong>⚠️ Security Notice:</strong>
              <ul style="margin: 10px 0;">
                <li>This link will expire in 1 hour</li>
                <li>For your security, this link can only be used once</li>
                <li>If you didn't request this, please ignore this email</li>
              </ul>
            </div>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} ${process.env.APP_NAME || 'User Management System'}. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Welcome email template
  getWelcomeEmailTemplate(userName, dashboardUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; padding: 12px 30px; background: #4facfe; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Welcome!</h1>
          </div>
          <div class="content">
            <p>Hi <strong>${userName}</strong>,</p>
            <p>Welcome to ${process.env.APP_NAME || 'User Management System'}! Your account has been successfully verified and is now active.</p>
            <p>You can now access all features of your account:</p>
            <div style="text-align: center;">
              <a href="${dashboardUrl}" class="button">Go to Dashboard</a>
            </div>
            <p>If you have any questions or need assistance, feel free to reach out to our support team.</p>
            <p>Thank you for joining us!</p>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} ${process.env.APP_NAME || 'User Management System'}. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Password changed template
  getPasswordChangedEmailTemplate(userName, supportUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .alert { background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 15px 0; }
          .button { display: inline-block; padding: 12px 30px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>✓ Password Changed</h1>
          </div>
          <div class="content">
            <p>Hi <strong>${userName}</strong>,</p>
            <div class="alert">
              <strong>✓ Success!</strong> Your password has been changed successfully.
            </div>
            <p><strong>If this was you:</strong> No further action is needed. Your account is secure.</p>
            <p><strong>If this wasn't you:</strong> Your account may have been compromised. Please contact support immediately:</p>
            <div style="text-align: center;">
              <a href="${supportUrl}" class="button">Contact Support</a>
            </div>
            <p><strong>Security Recommendations:</strong></p>
            <ul>
              <li>Use a strong, unique password</li>
              <li>Enable two-factor authentication</li>
              <li>Never share your password</li>
              <li>Review your recent account activity</li>
            </ul>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} ${process.env.APP_NAME || 'User Management System'}. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Account activation template (for bulk imports)
  getAccountActivationEmailTemplate(userName, tempPassword, loginUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .credentials { background: #fff; border: 2px solid #fee140; padding: 15px; margin: 20px 0; border-radius: 5px; }
          .button { display: inline-block; padding: 12px 30px; background: #fa709a; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }
          .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Your Account is Ready!</h1>
          </div>
          <div class="content">
            <p>Hi <strong>${userName}</strong>,</p>
            <p>An account has been created for you in ${process.env.APP_NAME || 'User Management System'}.</p>
            <div class="credentials">
              <h3 style="margin-top: 0;">Your Login Credentials:</h3>
              <p><strong>Email:</strong> ${userName}@example.com</p>
              <p><strong>Temporary Password:</strong> <code style="background: #f0f0f0; padding: 5px 10px; border-radius: 3px;">${tempPassword}</code></p>
            </div>
            <div style="text-align: center;">
              <a href="${loginUrl}" class="button">Log In Now</a>
            </div>
            <div class="warning">
              <strong>⚠️ Important Security Steps:</strong>
              <ol style="margin: 10px 0;">
                <li><strong>Change your password immediately</strong> after first login</li>
                <li>Do not share your credentials with anyone</li>
                <li>Enable two-factor authentication for added security</li>
              </ol>
            </div>
            <p>If you have any questions, please contact your administrator.</p>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} ${process.env.APP_NAME || 'User Management System'}. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  // Test email connection
  async testConnection() {
    try {
      await this.transporter.verify();
      logger.info('Email service connection verified successfully');
      return { success: true, message: 'Email service is configured correctly' };
    } catch (error) {
      logger.error('Email service connection failed:', error.message);
      return { success: false, message: 'Email service configuration error', error: error.message };
    }
  }
}

module.exports = new EmailService();