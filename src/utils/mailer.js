import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();
export const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
    },
  from: `"Servoro" <${process.env.EMAIL_USER}>`
});

export function sendVerificationEmail(to, token) {
  const link = `${process.env.BASE_URL}/verify-email?token=${token}`;
  return transporter.sendMail({
    from: `"Servoro" <${process.env.GMAIL_USER}>`,
    to,
    subject: 'Verify your email',
    html: `<p>Click the link to verify your email:</p><a href="${link}">${link}</a>`,
  });
}

export function sendResetPasswordEmail(to, token) {
  const link = `${process.env.BASE_URL}/reset-password?token=${token}`;
  return transporter.sendMail({
    from: `"Servoro" <${process.env.GMAIL_USER}>`,
    to,
    subject: 'Reset your password',
    html: `<p>Click below to reset your password (valid for 15 mins):</p><a href="${link}">${link}</a>`,
  });
}