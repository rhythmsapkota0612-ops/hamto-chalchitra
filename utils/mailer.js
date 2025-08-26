const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

async function sendPasswordReset(to, link) {
  const from = process.env.MAIL_FROM || "no-reply@example.com";
  const html = `
    <p>You requested a password reset.</p>
    <p>Click the link below to reset your password. It expires in ${
      process.env.PASSWORD_RESET_TTL_MIN || 30
    } minutes.</p>
    <p><a href="${link}" target="_blank">${link}</a></p>
    <p>If you didn't request this, you can ignore this email.</p>`;
  return transporter.sendMail({
    from,
    to,
    subject: "Reset your password",
    html,
  });
}

module.exports = { sendPasswordReset };
