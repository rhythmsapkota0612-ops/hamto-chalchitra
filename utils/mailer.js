const SibApiV3Sdk = require("sib-api-v3-sdk");

const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications["api-key"];
apiKey.apiKey = process.env.BREVO_API_KEY;

const transacApi = new SibApiV3Sdk.TransactionalEmailsApi();

async function sendPasswordReset(to, link) {
  const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();

  sendSmtpEmail.sender = {
    name: "Bravo App",
    email: process.env.MAIL_FROM || "no-reply@yourdomain.com",
  };

  sendSmtpEmail.to = [{ email: to }];

  sendSmtpEmail.subject = "Reset your password";
  sendSmtpEmail.htmlContent = `
    <p>You requested a password reset.</p>
    <p>Click the link below to reset your password. It expires in ${
      process.env.PASSWORD_RESET_TTL_MIN || 30
    } minutes.</p>
    <p><a href="${link}" target="_blank">${link}</a></p>
    <p>If you didn't request this, you can ignore this email.</p>
  `;

  try {
    const result = await transacApi.sendTransacEmail(sendSmtpEmail);
    console.log("✅ Reset email sent:", result.messageId);
    return result;
  } catch (err) {
    console.error("❌ Brevo send error:", err);
    throw err;
  }
}

module.exports = { sendPasswordReset };
