import nodemailer from 'nodemailer';

let transporterPromise;

// Ethereal hands out disposable fake SMTP credentials on demand — nothing is
// really delivered, but this transporter talks real SMTP, so swapping in a
// real provider later only means changing these connection details
function getTransporter() {
  if (!transporterPromise) {
    transporterPromise = nodemailer.createTestAccount().then((testAccount) =>
      nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
      })
    );
  }
  return transporterPromise;
}

export async function sendVerificationEmail(to, token) {
  const transporter = await getTransporter();
  const link = `http://localhost:3000/verify-email?token=${token}`;

  const info = await transporter.sendMail({
    from: '"Auth v2" <no-reply@auth-v2.test>',
    to,
    subject: 'Verify your email',
    html: `<p>Click to verify your account:</p><p><a href="${link}">${link}</a></p>`,
  });

  // Ethereal's stand-in for "check your inbox" — a real preview of the actual email sent
  console.log('Verification email preview:', nodemailer.getTestMessageUrl(info));
}

export async function sendPasswordResetEmail(to, token) {
  const transporter = await getTransporter();
  const link = `http://localhost:3000/reset-password?token=${token}`;

  const info = await transporter.sendMail({
    from: '"Auth v2" <no-reply@auth-v2.test>',
    to,
    subject: 'Reset your password',
    html: `<p>Click to reset your password:</p><p><a href="${link}">${link}</a></p>`,
  });

  console.log('Password reset email preview:', nodemailer.getTestMessageUrl(info));
}
