import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();
const appName = process.env.APP_NAME || 'Servoro';

export const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
    },
  from: `"${process.env.APP_NAME}" <${process.env.EMAIL_USER}>`,
});

export function sendVerificationEmail(to, token) {
  const link = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
  return transporter.sendMail({
    from: `"${process.env.APP_NAME}" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Verify your email address',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 24px; border: 1px solid #e5e5e5; border-radius: 8px;">
        <h2 style="color: #333;">Welcome to <span style="color:#4f46e5;">${appName}</span> 👋</h2>
        <p style="font-size: 15px; color: #555;">Please click the button below to verify your email address and activate your account.</p>

        <a href="${link}" target="_blank" style="display: inline-block; padding: 12px 20px; margin: 20px 0; background-color: #4f46e5; color: white; text-decoration: none; border-radius: 6px;">Verify Email</a>

        <p style="font-size: 13px; color: #888;">Or copy and paste this URL into your browser:</p>
        <p style="font-size: 13px; color: #4f46e5;">${link}</p>

        <hr style="margin: 32px 0;" />

        <p style="font-size: 12px; color: #999;">If you didn’t create an account with ${appName}, you can safely ignore this email.</p>
      </div>
    `,
  });
}
export function sendResetPasswordEmail(to, token) {
  const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
  return transporter.sendMail({
    from: `"${process.env.APP_NAME}" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Reset your password',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 24px; border: 1px solid #e5e5e5; border-radius: 8px;">
        <h2 style="color: #333;">Reset your password 🔐</h2>
        <p style="font-size: 15px; color: #555;">You requested to reset your password. Click the button below to proceed. This link is valid for 15 minutes.</p>

        <a href="${link}" target="_blank" style="display: inline-block; padding: 12px 20px; margin: 20px 0; background-color: #4f46e5; color: white; text-decoration: none; border-radius: 6px;">Reset Password</a>

        <p style="font-size: 13px; color: #888;">Or copy and paste this URL into your browser:</p>
        <p style="font-size: 13px; color: #4f46e5;">${link}</p>

        <hr style="margin: 32px 0;" />

        <p style="font-size: 12px; color: #999;">If you didn’t request this password reset, you can safely ignore this email.</p>
      </div>
    `,
  });
}